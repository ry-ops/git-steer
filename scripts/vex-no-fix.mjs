/**
 * VEX alerts that have no fix available — OpenVEX-compliant (ADR-004 C-004-003).
 *
 * Daily-autonomous (wired into the heartbeat). For every managed repo:
 *   1. Fetch ALL open Dependabot alerts (paginated).
 *   2. Identify alerts where no patched version exists.
 *   3. Record canonical VEX `under_investigation` entries in the git-steer-state
 *      `_vex` store + vex.jsonl ledger (the SAME shape/validator the MCP/web
 *      stores use), AND
 *   4. Open/refresh a documenting PR in the TARGET repo that commits an OpenVEX
 *      document at `.well-known/openvex/no-fix.openvex.json` — a visible,
 *      machine-consumable artifact stating that no fix is currently available.
 *      Doc-only, so it's merged directly (no functional-integrity gate needed).
 *
 * `under_investigation` is the honest automated state for a no-fix finding: it
 * is tracked, not ignored, and the heartbeat re-evaluates it (C-004-005). A
 * maintainer later promotes it to not_affected (+justification) or affected
 * (+action_statement) via the vex_set MCP tool or the web API.
 *
 * Dual auth: GH_TOKEN in CI (heartbeat), macOS Keychain (keytar) locally.
 * Build first: `npm run build` (imports compiled dist/core/vex.js).
 */

import { App, Octokit } from 'octokit';
import { validateVexInput, vexId, makeVexLedgerEntry, toOpenVex } from '../dist/core/vex.js';
import { appendJsonl } from './lib/state-jsonl.mjs';

const STATE_REPO = 'git-steer-state';
const VEX_PATH = '.well-known/openvex/no-fix.openvex.json';
const VEX_BRANCH = 'security/vex-no-fix';

// ── Dual auth ─────────────────────────────────────────────────────────
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

// ── PURL for SBOM linkage (C-004-004) ─────────────────────────────────
const PURL_TYPE = { npm: 'npm', pip: 'pypi', go: 'golang', gomod: 'golang', maven: 'maven', nuget: 'nuget', rubygems: 'gem', composer: 'composer', rust: 'cargo', cargo: 'cargo' };
function toPurl(ecosystem, name) {
  const type = PURL_TYPE[(ecosystem || '').toLowerCase()] || (ecosystem || 'generic').toLowerCase();
  return `pkg:${type}/${name}`;
}

// ── 1. Fetch all repos ────────────────────────────────────────────────
const { data } = await octokit.request('GET /installation/repositories', { per_page: 100 });
const repos = data.repositories.filter((r) => !r.archived);
console.log(`Scanning ${repos.length} repos for alerts without fixes...\n`);

// ── 2. Fetch alerts (paginated) and split by fix availability ─────────
const noFixAlerts = [];
let hasFixCount = 0;

for (const repo of repos) {
  try {
    const alerts = await octokit.paginate('GET /repos/{owner}/{repo}/dependabot/alerts', {
      owner: repo.owner.login, repo: repo.name, state: 'open', per_page: 100,
    });
    for (const alert of alerts) {
      const fixVersion = alert.security_vulnerability?.first_patched_version?.identifier ?? null;
      if (fixVersion) { hasFixCount++; continue; }
      const ecosystem = alert.dependency?.package?.ecosystem ?? 'unknown';
      const pkg = alert.dependency?.package?.name ?? 'unknown';
      noFixAlerts.push({
        owner: repo.owner.login,
        repo: repo.name,
        cve: alert.security_advisory?.cve_id || alert.security_advisory?.ghsa_id || `GHSA-alert-${alert.number}`,
        package: pkg,
        ecosystem,
        severity: alert.security_advisory?.severity || 'unknown',
        purl: toPurl(ecosystem, pkg),
      });
    }
    process.stdout.write('.');
  } catch {
    process.stdout.write('x');
  }
}

console.log('\n');
console.log(`No fix available: ${noFixAlerts.length} (will VEX)   |   With fix: ${hasFixCount}\n`);

if (noFixAlerts.length === 0) {
  console.log('Nothing to VEX — all alerts have fixes available.');
  process.exit(0);
}

// ── 3. Load existing _vex from git-steer-state ────────────────────────
const owner = repos[0].owner.login;

let cacheJson = {};
let cacheSha = null;
try {
  const { data: file } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
    owner, repo: STATE_REPO, path: 'state/cache.json',
  });
  cacheSha = file.sha;
  cacheJson = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));
} catch {
  console.log('No existing cache.json found, creating fresh.');
}

const existingVex = cacheJson._vex || {};
const now = new Date().toISOString();
let newVexCount = 0;
const ledgerRows = [];

// ── 4. Create canonical, validated VEX entries ────────────────────────
for (const alert of noFixAlerts) {
  const repoFull = `${alert.owner}/${alert.repo}`;
  const id = vexId(repoFull, alert.cve);
  if (existingVex[id]) continue; // already tracked

  const entry = {
    cve_id: alert.cve,
    repo: repoFull,
    product_purl: alert.purl,
    status: 'under_investigation',
    detail: `No upstream fix available. Package: ${alert.package} (${alert.severity}). Auto-tracked; pending exploitability assessment.`,
    created_at: now,
    updated_by: 'git-steer-cli-vex-no-fix',
  };

  const error = validateVexInput(entry);
  if (error) { console.warn(`  [skip] ${id}: ${error}`); continue; }

  existingVex[id] = entry;
  ledgerRows.push(makeVexLedgerEntry(entry, null, 'cli:vex-no-fix', now));
  newVexCount++;
}

cacheJson._vex = existingVex;
console.log(`VEX entries created: ${newVexCount} new (${Object.keys(existingVex).length} total in state)\n`);

// ── 5. Persist state ──────────────────────────────────────────────────
const content = Buffer.from(JSON.stringify(cacheJson, null, 2)).toString('base64');
await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner, repo: STATE_REPO, path: 'state/cache.json',
  message: `vex: track ${newVexCount} no-fix alerts as under_investigation (OpenVEX)`,
  content,
  ...(cacheSha ? { sha: cacheSha } : {}),
});
await appendJsonl(octokit, owner, STATE_REPO, 'state/vex.jsonl', ledgerRows);
console.log(`State saved. (${ledgerRows.length} ledger rows appended)\n`);

// ── 6. Open/refresh a documenting PR per affected repo ────────────────
const byRepo = {};
for (const a of noFixAlerts) (byRepo[`${a.owner}/${a.repo}`] ??= []).push(a);

/** Commit the OpenVEX doc to a branch, open/refresh a PR, and merge it. */
async function upsertVexDocPr(repoFull, alerts) {
  const [ro, rn] = repoFull.split('/');
  // Build the OpenVEX doc from this scan's no-fix set (authoritative "current").
  const entries = alerts.map((a) => ({
    cve_id: a.cve, repo: repoFull, product_purl: a.purl,
    status: 'under_investigation',
    detail: `No upstream fix available for ${a.package} (${a.severity}).`,
    created_at: now, updated_by: 'cli:vex-no-fix',
  }));
  const doc = toOpenVex(repoFull, entries, `https://ry-ops.dev/vex/${repoFull}/no-fix`, now);
  const newBody = JSON.stringify(doc, null, 2) + '\n';
  // stable signature (statements only) so a timestamp-only delta doesn't churn
  const sig = (d) => JSON.stringify(d.statements);

  const base = (await octokit.rest.repos.get({ owner: ro, repo: rn })).data.default_branch;

  // skip if the doc already on the default branch matches (no change to make)
  try {
    const { data: f } = await octokit.rest.repos.getContent({ owner: ro, repo: rn, path: VEX_PATH, ref: base });
    const cur = JSON.parse(Buffer.from(f.content, 'base64').toString('utf-8'));
    if (sig(cur) === sig(doc)) { console.log(`  ${repoFull}: VEX doc already current — no PR`); return; }
  } catch { /* doc doesn't exist yet */ }

  // (re)create the branch at base
  const baseSha = (await octokit.rest.git.getRef({ owner: ro, repo: rn, ref: `heads/${base}` })).data.object.sha;
  try {
    await octokit.rest.git.updateRef({ owner: ro, repo: rn, ref: `heads/${VEX_BRANCH}`, sha: baseSha, force: true });
  } catch {
    await octokit.rest.git.createRef({ owner: ro, repo: rn, ref: `refs/heads/${VEX_BRANCH}`, sha: baseSha });
  }

  // commit the doc on the branch
  let fileSha;
  try {
    fileSha = (await octokit.rest.repos.getContent({ owner: ro, repo: rn, path: VEX_PATH, ref: VEX_BRANCH })).data.sha;
  } catch { /* new file */ }
  await octokit.rest.repos.createOrUpdateFileContents({
    owner: ro, repo: rn, path: VEX_PATH, branch: VEX_BRANCH,
    message: `security(vex): document ${alerts.length} dependency advisory(ies) with no upstream fix`,
    content: Buffer.from(newBody).toString('base64'),
    ...(fileSha ? { sha: fileSha } : {}),
  });

  // PR body (human-readable documentation)
  const rows = alerts.map((a) => `| \`${a.cve}\` | ${a.package} | ${a.severity.toUpperCase()} | \`${a.purl}\` |`).join('\n');
  const body = [
    '## Dependencies with no upstream fix (OpenVEX)',
    '',
    `git-steer's daily scan found **${alerts.length}** open Dependabot alert(s) on this repo for which **no patched version is currently available**. They cannot be auto-remediated by a version bump, so they are documented here as OpenVEX \`under_investigation\` — visible and machine-consumable — rather than silently ignored.`,
    '',
    '| CVE / GHSA | Package | Severity | PURL |',
    '|---|---|---|---|',
    rows,
    '',
    `Artifact: \`${VEX_PATH}\` (OpenVEX 0.2.0). Regenerated each scan; entries clear automatically when an upstream fix lands. A maintainer should assess exploitability and promote each to \`not_affected\` (+justification) or \`affected\` (+action_statement).`,
    '',
    'Generated by [git-steer](https://github.com/ry-ops/git-steer) · ADR-004 C-004-003',
  ].join('\n');

  for (const [n, c] of [['security', 'd73a4a'], ['automated', 'bfd4f2'], ['vex', '5319e7']]) {
    try { await octokit.rest.issues.createLabel({ owner: ro, repo: rn, name: n, color: c }); } catch { /* exists */ }
  }

  let pr = (await octokit.rest.pulls.list({ owner: ro, repo: rn, head: `${ro}:${VEX_BRANCH}`, state: 'open' })).data[0];
  if (pr) {
    await octokit.rest.pulls.update({ owner: ro, repo: rn, pull_number: pr.number, title: `security(vex): ${alerts.length} dependency advisory(ies) with no fix`, body });
  } else {
    pr = (await octokit.rest.pulls.create({ owner: ro, repo: rn, head: VEX_BRANCH, base, title: `security(vex): ${alerts.length} dependency advisory(ies) with no fix`, body })).data;
  }
  try { await octokit.rest.issues.addLabels({ owner: ro, repo: rn, issue_number: pr.number, labels: ['security', 'automated', 'vex'] }); } catch { /* */ }

  // doc-only change -> merge directly; if branch protection blocks, hold for human
  try {
    await octokit.rest.pulls.merge({ owner: ro, repo: rn, pull_number: pr.number, merge_method: 'squash',
      commit_title: `security(vex): document ${alerts.length} no-fix advisory(ies)` });
    console.log(`  ${repoFull}: VEX doc PR #${pr.number} merged`);
  } catch {
    try {
      await octokit.rest.issues.addLabels({ owner: ro, repo: rn, issue_number: pr.number, labels: ['needs-human-merge'] });
    } catch { /* */ }
    console.log(`  ${repoFull}: VEX doc PR #${pr.number} open (merge blocked by branch protection — needs human)`);
  }
}

console.log('Publishing OpenVEX documentation PRs...');
for (const [repoFull, alerts] of Object.entries(byRepo)) {
  try { await upsertVexDocPr(repoFull, alerts); }
  catch (e) { console.warn(`  ${repoFull}: VEX doc PR failed — ${e.message}`); }
}

// ── 7. Report ─────────────────────────────────────────────────────────
console.log('');
for (const [repoName, alerts] of Object.entries(byRepo)) {
  console.log(`${repoName}: ${alerts.length} no-fix alert(s)`);
  for (const a of alerts) console.log(`  [${a.severity.toUpperCase()}] ${a.package} (${a.cve}) → ${a.purl}`);
}
