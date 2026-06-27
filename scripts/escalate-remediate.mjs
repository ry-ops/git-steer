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
// Strict owner/repo shape: bounds the charset (GitHub names are
// [A-Za-z0-9._-]) so `target` can never carry a path-traversal or a
// prototype-polluting key (__proto__/constructor/prototype) into the
// `esc[target]` / `_vex[...]` object writes below.
const REPO_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const DANGEROUS = new Set(['__proto__', 'constructor', 'prototype']);
if (!target || !REPO_RE.test(target) || target.split('/').some((s) => DANGEROUS.has(s))) {
  console.error('Usage: node scripts/escalate-remediate.mjs <owner/repo> [--threshold N]');
  process.exit(2);
}
const [tOwner, tRepo] = target.split('/');
const tIdx = process.argv.indexOf('--threshold');
const THRESHOLD = tIdx >= 0 ? Number(process.argv[tIdx + 1]) : 3;
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

const slug = (d) => d.replace(/[/ ]/g, '-').replace(/^\.$/, 'root');
const manifestDir = (m) => (m && m.includes('/') ? m.split('/').slice(0, -1).join('/') : '.');

// ── discover the buildable units (package dirs) with a fixable alert ───
async function discoverPackages() {
  const alerts = await octokit.paginate('GET /repos/{owner}/{repo}/dependabot/alerts', {
    owner: tOwner, repo: tRepo, state: 'open', per_page: 100,
  });
  const dirs = new Set();
  for (const a of alerts) {
    if (!a.security_vulnerability?.first_patched_version?.identifier) continue; // no-fix → vex-no-fix
    dirs.add(manifestDir(a.dependency?.manifest_path || ''));
  }
  return [...dirs];
}

// ── dispatch ONE package, wait for its run, report held / merged ──────
// ADR-007: per-package scope. Each package is gated and auto-merged on its own,
// so the clean packages land without a human and only a genuinely-broken one is
// held — instead of one bad package holding the whole repo's fixes hostage.
async function runPackage(pkgDir) {
  const branch = `security/fix-${slug(pkgDir)}`;
  const before = (await octokit.rest.actions.listWorkflowRuns({ ...STEER, workflow_id: WORKER, per_page: 1 }))
    .data.workflow_runs[0]?.id ?? 0;

  await octokit.rest.actions.createWorkflowDispatch({
    ...STEER, workflow_id: WORKER, ref: 'main',
    inputs: { target_repo: target, severity: 'all', package_dir: pkgDir, dry_run: 'false' },
  });

  let run = null;
  for (let i = 0; i < 90; i++) {
    await sleep(8000);
    const runs = (await octokit.rest.actions.listWorkflowRuns({ ...STEER, workflow_id: WORKER, per_page: 8 })).data.workflow_runs;
    run = runs.find((r) => r.id > before);
    if (run && run.status === 'completed') break;
  }
  if (!run) return { sev: pkgDir, outcome: 'error', detail: 'no run observed' };

  const open = (await octokit.rest.pulls.list({ owner: tOwner, repo: tRepo, head: `${tOwner}:${branch}`, state: 'open' })).data;
  if (open.length) {
    let verdict = 'held';
    try {
      const comments = (await octokit.rest.issues.listComments({ owner: tOwner, repo: tRepo, issue_number: open[0].number })).data;
      const gc = [...comments].reverse().find((c) => /Functional-integrity gate/.test(c.body));
      verdict = gc?.body.match(/gate: ([A-Z-]+)/)?.[1] ?? 'held';
    } catch { /* */ }
    return { sev: pkgDir, outcome: 'held', verdict, pr: open[0].number };
  }
  return { sev: pkgDir, outcome: run.conclusion === 'success' ? 'merged_or_nochange' : 'error', detail: run.conclusion };
}

// ── sweep EVERY package (no early stop) ───────────────────────────────
console.log(`\n=== ADR-006/007 per-package sweep: ${target} (hard-stop threshold ${THRESHOLD} sweeps) ===\n`);
const packages = await discoverPackages();
console.log(`  packages with a fixable alert: ${packages.length ? packages.join(', ') : '(none)'}\n`);
let floor = null;
const trail = [];
for (const pkgDir of packages) {
  process.stdout.write(`  package ${pkgDir}... `);
  const r = await runPackage(pkgDir);
  trail.push(r);
  console.log(r.outcome === 'held' ? `HELD (${r.verdict}) PR#${r.pr}` : r.outcome);
  // the repo's residual "floor" is the first package that stayed held/errored
  if (!floor && (r.outcome === 'held' || r.outcome === 'error')) floor = r;
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

// ── terminal disposition: every CVE residual ends FIXED or VEX'd ──────
// The ADR-004 contract is simple: if there's a fix, apply it; if there isn't,
// VEX it until one exists. A held PR (genuine gate NO-GO) is a human's call.
// But a NO-OP fall-out means the bump worker CANNOT produce a fix (transitive /
// not directly bumpable) — that is exactly "no fix available", so it gets a VEX
// `under_investigation` on the FIRST sweep, not after looping to the hard-stop.
// At the hard-stop threshold the residual escalates to `affected` (human review).
// The VEX key is stable per repo so the lifecycle under_investigation -> affected
// -> fixed tracks one entry the dashboard can read.
const RESIDUAL_CVE = `escalation/${target}#residual`;
async function setResidualVex(status, actionStatement) {
  const entry = {
    cve_id: RESIDUAL_CVE,
    repo: target,
    product_purl: `pkg:github/${target}`,
    status,
    detail: `ADR-006 residual${floor ? `: floor ${floor.sev} (${floor.verdict ?? floor.detail})` : ' cleared'}`.slice(0, 480),
    created_at: now,
    updated_by: 'cli:escalate-remediate',
  };
  if (status === 'affected') entry.action_statement = actionStatement;
  // validateVexInput returns an error string when INVALID, null when valid.
  if (validateVexInput(entry)) return;
  const fresh = (await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner: STEER.owner, repo: STATE_REPO, path: 'state/cache.json' })).data;
  const c2 = JSON.parse(Buffer.from(fresh.content, 'base64').toString('utf-8'));
  c2._vex = c2._vex ?? {};
  const key = vexId(target, RESIDUAL_CVE);
  const prev = c2._vex[key]?.status ?? null;
  if (prev === status) return;                              // idempotent — already in this state
  if (status === 'fixed' && prev === null) return;          // nothing to lift; don't manufacture a record
  c2._vex[key] = entry;
  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner: STEER.owner, repo: STATE_REPO, path: 'state/cache.json',
    message: `vex: residual ${status} for ${target} (ADR-006)`,
    content: Buffer.from(JSON.stringify(c2, null, 2)).toString('base64'),
    sha: fresh.sha,
  });
  await appendJsonl(octokit, STEER.owner, STATE_REPO, 'state/vex.jsonl', [makeVexLedgerEntry(entry, prev, 'cli:escalate-remediate', now)]);
  console.log(`  VEX residual ${prev ?? 'new'} -> ${status} for ${target}`);
}

if (floor) {
  if (hardStop) {
    const num = floor.pr ?? trackingIssue;
    const ref = floor.pr ? `PR#${floor.pr}` : trackingIssue ? `issue #${trackingIssue}` : 'no artifact';
    if (num) { try { await octokit.rest.issues.addLabels({ owner: tOwner, repo: tRepo, issue_number: num, labels: ['escalation:hard-stop'] }); } catch { /* */ } }
    await setResidualVex('affected', `Autonomous remediation exhausted the ADR-006 ladder for ${THRESHOLD}+ consecutive sweeps; floor=${floor.sev}, ${remaining} dep(s) remain (${floor.verdict ?? floor.detail}). Held for human review at ${ref}.`);
  } else if (!floor.pr) {
    // residual the bump worker couldn't fix (no PR producible) → VEX now
    await setResidualVex('under_investigation');
  }
} else {
  // genuinely cleared (0 deps remain) → lift any residual VEX to fixed
  await setResidualVex('fixed');
}

console.log(`\n=== trail ===`);
for (const r of trail) console.log(`  ${r.sev.padEnd(8)} ${r.outcome}${r.verdict ? ' ('+r.verdict+')' : ''}`);
