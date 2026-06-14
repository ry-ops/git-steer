/**
 * vex-history.mjs — look up VEX history from the append-only vex.jsonl ledger
 * in git-steer-state (who/what/when, before -> after), plus current status
 * from the _vex map.
 *
 * Usage:
 *   node scripts/vex-history.mjs                         # all changes, newest first
 *   node scripts/vex-history.mjs --repo ry-ops/git-steer
 *   node scripts/vex-history.mjs --cve codeql/js/user-controlled-bypass#42
 *   node scripts/vex-history.mjs --status under_investigation
 *   node scripts/vex-history.mjs --current               # show current _vex map only
 */

import keytar from 'keytar';
import { App } from 'octokit';

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true) : undefined;
};
const fRepo = flag('--repo');
const fCve = flag('--cve');
const fStatus = flag('--status');
const currentOnly = flag('--current') === true;

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');
const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

const owner = (await octokit.request('GET /installation/repositories', { per_page: 1 })).data.repositories[0].owner.login;
const STATE_REPO = 'git-steer-state';

async function readState(path) {
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner, repo: STATE_REPO, path });
    return Buffer.from(data.content, 'base64').toString('utf-8');
  } catch { return ''; }
}

// ── Current state (from _vex map in cache.json) ───────────────────────
const cacheRaw = await readState('state/cache.json');
const vexMap = cacheRaw ? (JSON.parse(cacheRaw)._vex ?? {}) : {};
let current = Object.values(vexMap);
if (fRepo) current = current.filter((e) => e.repo === fRepo);
if (fCve) current = current.filter((e) => e.cve_id === fCve);
if (fStatus) current = current.filter((e) => e.status === fStatus);

const STATUS_ICON = { not_affected: '🟢', fixed: '✅', affected: '🔴', under_investigation: '🟡' };

console.log(`\n=== CURRENT VEX (${current.length}) ===`);
for (const e of current.sort((a, b) => (a.repo + a.cve_id).localeCompare(b.repo + b.cve_id))) {
  console.log(`${STATUS_ICON[e.status] ?? '  '} ${e.status.padEnd(20)} ${e.repo}  ${e.cve_id}`);
  console.log(`     ${e.justification || e.action_statement || ''}${e.product_purl ? '  [' + e.product_purl + ']' : ''}`);
}

// ── History (from append-only vex.jsonl ledger) — skipped in --current mode ──
if (!currentOnly) {
  const ledgerRaw = await readState('state/vex.jsonl');
  let rows = ledgerRaw.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
  if (fRepo) rows = rows.filter((r) => r.repo === fRepo);
  if (fCve) rows = rows.filter((r) => r.cve_id === fCve);
  if (fStatus) rows = rows.filter((r) => r.status === fStatus);
  rows.sort((a, b) => b.ts.localeCompare(a.ts)); // newest first

  console.log(`\n=== HISTORY (${rows.length} change${rows.length === 1 ? '' : 's'}, newest first) ===`);
  if (rows.length === 0) {
    console.log('  (no ledger rows — state/vex.jsonl is empty or absent)');
  } else {
    for (const r of rows) {
      const transition = r.prev_status ? `${r.prev_status} → ${r.status}` : `(new) ${r.status}`;
      console.log(`${r.ts}  ${r.repo}  ${r.cve_id}`);
      console.log(`     ${transition.padEnd(34)} via ${r.source} (${r.updated_by})`);
      if (r.justification) console.log(`     justification: ${r.justification}`);
      if (r.action_statement) console.log(`     action: ${r.action_statement}`);
    }
  }
  console.log('');
}
