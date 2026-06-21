/**
 * escalate-remediate.mjs — ADR-006 Autonomous Remediation Control Loop (v1).
 *
 * Turns the all-or-nothing security-fix-worker into a graduated ladder:
 * dispatch the GATED worker at escalating severity scopes (critical -> high ->
 * medium -> low). Each scope that the ADR-005 gate clears (GO) auto-merges;
 * the loop STOPS at the first scope that holds (NO-GO / GO-UNVERIFIED), having
 * already merged every safer scope. Instead of holding a whole 240-CVE repo,
 * it merges the criticals that build and holds only the residual.
 *
 * Sweep-persistence (ADR-006 C-006-008): a repo that falls out of the ladder
 * has its consecutive-fallout counter incremented in git-steer-state
 * (state/cache.json `_escalation`). The human HARD-STOP (VEX affected +
 * escalation:hard-stop label) is enforced ONLY at the persistence threshold
 * (default 3 sweeps). Below it, the repo stays in the loop and is re-attempted
 * next sweep — an upstream patch may resolve it without a human. The counter
 * resets the moment the repo fully clears.
 *
 * Build first: `npm run build`.
 * Usage: node scripts/escalate-remediate.mjs <owner/repo> [--threshold N]
 */

import { App, Octokit } from 'octokit';
import { validateVexInput, vexId, makeVexLedgerEntry } from '../dist/core/vex.js';
import { appendJsonl } from './lib/state-jsonl.mjs';

const target = process.argv[2];
if (!target || !target.includes('/')) {
  console.error('Usage: node scripts/escalate-remediate.mjs <owner/repo> [--threshold N]');
  process.exit(2);
}
const [tOwner, tRepo] = target.split('/');
const tIdx = process.argv.indexOf('--threshold');
const THRESHOLD = tIdx >= 0 ? Number(process.argv[tIdx + 1]) : 3;
const LADDER = ['critical', 'high', 'medium', 'low'];
const WORKER = 'security-fix-worker.yml';
const STEER = { owner: 'ry-ops', repo: 'git-steer' };
const STATE_REPO = 'git-steer-state';

// Dual auth: GH_TOKEN in CI (heartbeat), macOS Keychain (keytar) locally.
let octokit;
if (process.env.GH_TOKEN) {
  octokit = new Octokit({ auth: process.env.GH_TOKEN });
} else {
  const keytar = (await import('keytar')).default;
  const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
  const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
  const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');
  const app = new App({ appId, privateKey });
  octokit = await app.getInstallationOctokit(Number(installationId));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── dispatch one rung and wait for its run to finish ──────────────────
async function runRung(sev) {
  const branch = `security/fix-${sev}`;
  const before = (await octokit.rest.actions.listWorkflowRuns({ ...STEER, workflow_id: WORKER, per_page: 1 }))
    .data.workflow_runs[0]?.id ?? 0;

  await octokit.rest.actions.createWorkflowDispatch({
    ...STEER, workflow_id: WORKER, ref: 'main',
    inputs: { target_repo: target, severity: sev, dry_run: 'false' },
  });

  // wait for the new run to appear + complete
  let run = null;
  for (let i = 0; i < 60; i++) {
    await sleep(8000);
    const runs = (await octokit.rest.actions.listWorkflowRuns({ ...STEER, workflow_id: WORKER, per_page: 5 })).data.workflow_runs;
    run = runs.find((r) => r.id > before);
    if (run && run.status === 'completed') break;
  }
  if (!run) return { sev, outcome: 'error', detail: 'no run observed' };

  // outcome: open held PR on this scope's branch? else merged / no-change
  const open = (await octokit.rest.pulls.list({ owner: tOwner, repo: tRepo, head: `${tOwner}:${branch}`, state: 'open' })).data;
  if (open.length) {
    const labels = open[0].labels.map((l) => l.name);
    let verdict = 'held';
    try {
      const comments = (await octokit.rest.issues.listComments({ owner: tOwner, repo: tRepo, issue_number: open[0].number })).data;
      const gc = [...comments].reverse().find((c) => /Functional-integrity gate/.test(c.body));
      verdict = gc?.body.match(/gate: ([A-Z-]+)/)?.[1] ?? 'held';
    } catch { /* */ }
    return { sev, outcome: 'held', verdict, pr: open[0].number, labels };
  }
  return { sev, outcome: run.conclusion === 'success' ? 'merged_or_nochange' : 'error', detail: run.conclusion };
}

// ── run the ladder ────────────────────────────────────────────────────
console.log(`\n=== ADR-006 escalation: ${target} (hard-stop threshold ${THRESHOLD} sweeps) ===\n`);
let floor = null;
const trail = [];
for (const sev of LADDER) {
  process.stdout.write(`  rung ${sev}... `);
  const r = await runRung(sev);
  trail.push(r);
  console.log(r.outcome === 'held' ? `HELD (${r.verdict}) PR#${r.pr}` : r.outcome);
  if (r.outcome === 'held') { floor = r; break; }
  if (r.outcome === 'error') { floor = r; break; }
}

// ── genuine-clear check: a no-op ladder with deps still open is NOT cleared ──
let remaining = 0;
try {
  remaining = (await octokit.paginate('GET /repos/{owner}/{repo}/dependabot/alerts', { owner: tOwner, repo: tRepo, state: 'open', per_page: 100 })).length;
} catch { /* alerts unreadable */ }
// Merged/skipped every rung but deps remain => silent fall-out (transitive /
// unfixable by the bump worker). Count it toward the hard-stop; do NOT reset.
if (!floor && remaining > 0) {
  floor = { sev: 'no-op', verdict: `worker no-op; ${remaining} dep(s) remain — likely transitive, needs lock-regen/manual` };
  console.log(`\n  ⚠ no merges but ${remaining} dep(s) remain — counting as a fall-out, not a clear`);
}

// ── visibility: every fall-out leaves a visible GitHub artifact ───────
// Held rungs already produced a PR. A no-op fall-out has none, so ensure an
// (idempotent) tracking issue exists — nothing is silently un-remediated.
async function ensureTrackingIssue(falloutCount, nowStr) {
  const title = `[security] ${tRepo}: dependency residual stuck in the ADR-006 loop`;
  let issue = (await octokit.rest.issues.listForRepo({ owner: tOwner, repo: tRepo, state: 'open', per_page: 100 })).data
    .find((i) => i.title === title && !i.pull_request);
  const sweepNote = `Sweep ${nowStr.slice(0, 10)}: **${remaining}** dep(s) open · floor \`${floor.sev}\` · fall-out ${falloutCount}/${THRESHOLD}.`;
  if (issue) {
    try { await octokit.rest.issues.createComment({ owner: tOwner, repo: tRepo, issue_number: issue.number, body: sweepNote }); } catch { /* */ }
    return issue.number;
  }
  try {
    issue = (await octokit.rest.issues.create({
      owner: tOwner, repo: tRepo, title,
      body: `Autonomous remediation (ADR-006) ran, but the dependency-bump worker made **no mergeable change** — the residual is likely transitive and needs lock-regen or a manual fix. This issue tracks the repo while it stays in the escalation loop; it hard-stops to human review after ${THRESHOLD} consecutive sweeps.\n\n${sweepNote}`,
      labels: ['security', 'automated'],
    })).data;
    return issue.number;
  } catch { return null; }
}

// ── persistence (ADR-006 C-006-008) ───────────────────────────────────
const { data: file } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner: STEER.owner, repo: STATE_REPO, path: 'state/cache.json' });
const cache = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));
const esc = cache._escalation ?? {};
const now = new Date().toISOString();
const prev = esc[target]?.consecutive_fallouts ?? 0;

let hardStop = false;
let trackingIssue = null;
if (floor) {
  const count = prev + 1;
  // a no-op fall-out has no fix PR -> open/refresh a visible tracking issue
  if (!floor.pr) { try { trackingIssue = await ensureTrackingIssue(count, now); } catch { /* */ } }
  esc[target] = { consecutive_fallouts: count, last_floor: floor.sev, last_verdict: floor.verdict ?? floor.detail, remaining, artifact: floor.pr ? `PR#${floor.pr}` : trackingIssue ? `issue#${trackingIssue}` : null, updated: now };
  hardStop = count >= THRESHOLD;
  const art = floor.pr ? `PR#${floor.pr}` : trackingIssue ? `issue #${trackingIssue}` : '(no artifact)';
  console.log(`\n  floor: ${floor.sev} (${floor.verdict ?? floor.detail}) | fall-outs: ${count}/${THRESHOLD} | ${art}`);
  if (hardStop) console.log(`  ⛔ PERSISTENCE THRESHOLD REACHED — enforcing human hard-stop`);
  else console.log(`  ↻ below threshold — stays in the loop, re-attempted next sweep`);
} else {
  esc[target] = { consecutive_fallouts: 0, last_floor: null, remaining: 0, cleared_at: now, updated: now };
  console.log(`\n  ✅ genuinely cleared (0 deps remain) — counter reset to 0`);
}

cache._escalation = esc;
await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner: STEER.owner, repo: STATE_REPO, path: 'state/cache.json',
  message: `escalation: ${target} ${floor ? `held@${floor.sev} (${esc[target].consecutive_fallouts}/${THRESHOLD})` : 'cleared'}`,
  content: Buffer.from(JSON.stringify(cache, null, 2)).toString('base64'),
  sha: file.sha,
});

// ── enforce hard-stop at threshold: VEX affected + label PR/issue ─────
if (hardStop) {
  const num = floor.pr ?? trackingIssue;
  const ref = floor.pr ? `PR#${floor.pr}` : trackingIssue ? `issue #${trackingIssue}` : 'no artifact';
  if (num) { try { await octokit.rest.issues.addLabels({ owner: tOwner, repo: tRepo, issue_number: num, labels: ['escalation:hard-stop'] }); } catch { /* */ } }
  const entry = {
    cve_id: `escalation/${target}#fix-${floor.sev}`,
    repo: target,
    product_purl: `pkg:github/${target}`,
    status: 'affected',
    action_statement: `Autonomous remediation exhausted the ADR-006 ladder for ${THRESHOLD}+ consecutive sweeps; floor=${floor.sev}, ${remaining} dep(s) remain (${floor.verdict}). Held for human review at ${ref}.`,
    detail: `ADR-006 C-006-008 hard-stop.`,
    created_at: now,
    updated_by: 'cli:escalate-remediate',
  };
  if (!validateVexInput(entry)) {
    const fresh = (await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner: STEER.owner, repo: STATE_REPO, path: 'state/cache.json' })).data;
    const c2 = JSON.parse(Buffer.from(fresh.content, 'base64').toString('utf-8'));
    c2._vex = c2._vex ?? {};
    c2._vex[vexId(target, entry.cve_id)] = entry;
    await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
      owner: STEER.owner, repo: STATE_REPO, path: 'state/cache.json',
      message: `vex: hard-stop affected for ${target} (ADR-006 C-006-008)`,
      content: Buffer.from(JSON.stringify(c2, null, 2)).toString('base64'),
      sha: fresh.sha,
    });
    await appendJsonl(octokit, STEER.owner, STATE_REPO, 'state/vex.jsonl', [makeVexLedgerEntry(entry, null, 'cli:escalate-remediate', now)]);
    console.log(`  VEX affected written + escalation:hard-stop on ${ref}`);
  }
}

console.log(`\n=== trail ===`);
for (const r of trail) console.log(`  ${r.sev.padEnd(8)} ${r.outcome}${r.verdict ? ' ('+r.verdict+')' : ''}`);
