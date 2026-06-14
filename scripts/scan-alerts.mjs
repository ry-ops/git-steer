/**
 * scan-alerts.mjs — comprehensive fleet security scan (ADR-004 "report ALL").
 *
 * For every non-archived installation repo, reports open findings across BOTH
 * GitHub alert classes — Dependabot AND Code Scanning — fully paginated, all
 * severities. (The old version queried Dependabot only, unpaginated, so it
 * dropped code-scanning findings and truncated repos with >30 alerts.)
 *
 * For a single-repo, self-reconciling check use scripts/scan-verify.mjs.
 */

import keytar from 'keytar';
import { App } from 'octokit';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

const { data } = await octokit.request('GET /installation/repositories', { per_page: 100 });
const repos = data.repositories.filter((r) => !r.archived);

console.log(`Scanning ${repos.length} repos (dependabot + code-scanning, all severities)...\n`);

const SEVS = ['critical', 'high', 'medium', 'low'];
const blank = () => Object.fromEntries(SEVS.map((s) => [s, 0]));

async function paginate(path, owner, repo) {
  try {
    return await octokit.paginate(path, { owner, repo, state: 'open', per_page: 100 });
  } catch (err) {
    if (err.status === 403 || err.status === 404) return null; // feature off / no perm
    throw err;
  }
}

const fleet = { dep: blank(), scan: blank() };
const reposWithAlerts = [];
let grandTotal = 0;

for (const repo of repos) {
  const owner = repo.owner.login;
  const [dep, scan] = await Promise.all([
    paginate('GET /repos/{owner}/{repo}/dependabot/alerts', owner, repo.name),
    paginate('GET /repos/{owner}/{repo}/code-scanning/alerts', owner, repo.name),
  ]);

  const dCounts = blank();
  for (const a of dep ?? []) {
    const s = (a.security_advisory?.severity ?? 'low').toLowerCase();
    if (s in dCounts) { dCounts[s]++; fleet.dep[s]++; }
  }
  const sCounts = blank();
  for (const a of scan ?? []) {
    const s = (a.rule?.security_severity_level ?? a.rule?.severity ?? 'low').toLowerCase();
    if (s in sCounts) { sCounts[s]++; fleet.scan[s]++; }
  }

  const total = (dep?.length ?? 0) + (scan?.length ?? 0);
  if (total > 0) {
    reposWithAlerts.push({ name: repo.name, total, dep: dep?.length ?? 0, scan: scan?.length ?? 0, dCounts, sCounts });
    grandTotal += total;
  }
  process.stdout.write(total > 0 ? '!' : '.');
}

console.log('\n');

if (reposWithAlerts.length === 0) {
  console.log('No open security findings across the fleet!');
  process.exit(0);
}

reposWithAlerts.sort((a, b) => b.total - a.total);

const sevStr = (c) => SEVS.filter((s) => c[s]).map((s) => `${s[0].toUpperCase()}:${c[s]}`).join(' ');
console.log('=== FINDINGS BY REPO (most first) ===\n');
for (const r of reposWithAlerts) {
  console.log(`${r.name}  —  ${r.total} total`);
  if (r.dep) console.log(`   dependabot   ${r.dep}: ${sevStr(r.dCounts) || '-'}`);
  if (r.scan) console.log(`   code-scan    ${r.scan}: ${sevStr(r.sCounts) || '-'}`);
}

console.log(`\n=== FLEET TOTALS ===`);
console.log(`dependabot:    ${sevStr(fleet.dep) || 'none'}`);
console.log(`code-scanning: ${sevStr(fleet.scan) || 'none'}`);
console.log(`\nTotal: ${grandTotal} open findings across ${reposWithAlerts.length} repos`);
