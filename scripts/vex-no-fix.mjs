/**
 * VEX alerts that have no fix available — OpenVEX-compliant (ADR-004 C-004-003).
 *
 * 1. Fetches ALL open Dependabot alerts across repos (fully paginated)
 * 2. Identifies alerts where no patched version exists
 * 3. Writes canonical VEX entries (status "under_investigation", linked to the
 *    component PURL) into the git-steer-state `_vex` store — the SAME shape and
 *    validator the MCP/web stores use (imported from dist/core/vex.js)
 *
 * "under_investigation" is the honest automated state for a no-fix finding: it
 * is tracked, not ignored, and the heartbeat re-evaluates it (C-004-005). A
 * human/agent later promotes it to not_affected (+justification) or affected
 * (+action_statement) via the vex_set MCP tool or the web API.
 *
 * Build first: `npm run build` (imports compiled dist/core/vex.js).
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { validateVexInput, vexId } from '../dist/core/vex.js';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

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
const STATE_REPO = 'git-steer-state';
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
  newVexCount++;
}

cacheJson._vex = existingVex;
console.log(`VEX entries created: ${newVexCount} new (${Object.keys(existingVex).length} total in state)\n`);

// ── 5. Persist ────────────────────────────────────────────────────────
const content = Buffer.from(JSON.stringify(cacheJson, null, 2)).toString('base64');
await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner, repo: STATE_REPO, path: 'state/cache.json',
  message: `vex: track ${newVexCount} no-fix alerts as under_investigation (OpenVEX)`,
  content,
  ...(cacheSha ? { sha: cacheSha } : {}),
});
console.log('State saved.\n');

// ── 6. Report ─────────────────────────────────────────────────────────
const byRepo = {};
for (const a of noFixAlerts) {
  (byRepo[`${a.owner}/${a.repo}`] ??= []).push(a);
}
for (const [repoName, alerts] of Object.entries(byRepo)) {
  console.log(`${repoName}: ${alerts.length} no-fix alert(s)`);
  for (const a of alerts) console.log(`  [${a.severity.toUpperCase()}] ${a.package} (${a.cve}) → ${a.purl}`);
  console.log('');
}
