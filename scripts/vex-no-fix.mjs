/**
 * VEX alerts that have no fix available.
 *
 * 1. Fetches all open Dependabot alerts across repos
 * 2. Identifies alerts where no patched version exists
 * 3. Persists VEX entries (status: "affected") to git-steer-state repo
 * 4. Rescans to show updated counts
 */

import keytar from 'keytar';
import { App } from 'octokit';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// --- Step 1: Fetch all repos ---
const { data } = await octokit.request('GET /installation/repositories');
const repos = data.repositories.filter(r => !r.archived);
console.log(`Scanning ${repos.length} repos for alerts without fixes...\n`);

// --- Step 2: Fetch alerts and separate by fix availability ---
const noFixAlerts = [];
const hasFixAlerts = [];

for (const repo of repos) {
  try {
    const { data: alerts } = await octokit.request(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      { owner: repo.owner.login, repo: repo.name, state: 'open', per_page: 100 }
    );
    for (const alert of alerts) {
      const entry = {
        owner: repo.owner.login,
        repo: repo.name,
        alertNumber: alert.number,
        package: alert.dependency?.package?.name || 'unknown',
        severity: alert.security_advisory?.severity || 'unknown',
        cve: alert.security_advisory?.cve_id || alert.security_advisory?.ghsa_id || `GHSA-alert-${alert.number}`,
        fixVersion: alert.security_vulnerability?.first_patched_version?.identifier || null,
      };
      if (entry.fixVersion) {
        hasFixAlerts.push(entry);
      } else {
        noFixAlerts.push(entry);
      }
    }
    process.stdout.write('.');
  } catch {
    process.stdout.write('x');
  }
}

console.log('\n');
console.log(`Total open alerts: ${noFixAlerts.length + hasFixAlerts.length}`);
console.log(`  With fix available: ${hasFixAlerts.length}`);
console.log(`  No fix available:   ${noFixAlerts.length} (will VEX these)\n`);

if (noFixAlerts.length === 0) {
  console.log('Nothing to VEX — all alerts have fixes available.');
  process.exit(0);
}

// --- Step 3: Load existing VEX state from git-steer-state ---
const STATE_REPO = 'git-steer-state';
const owner = repos[0].owner.login;

let cacheJson = {};
let cacheSha = null;

try {
  const { data: file } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
    owner,
    repo: STATE_REPO,
    path: 'state/cache.json',
  });
  cacheSha = file.sha;
  cacheJson = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));
} catch (e) {
  console.log('No existing cache.json found, creating fresh.');
}

const existingVex = cacheJson._vex || {};

// --- Step 4: Create VEX entries for no-fix alerts ---
const now = new Date().toISOString();
let newVexCount = 0;

for (const alert of noFixAlerts) {
  const id = `${alert.owner}/${alert.repo}::${alert.cve}`;
  if (existingVex[id]) continue; // already VEX'd

  existingVex[id] = {
    id,
    owner: alert.owner,
    repo: alert.repo,
    cveId: alert.cve,
    status: 'affected',
    justification: null,
    detail: `No fix available from upstream. Package: ${alert.package}, severity: ${alert.severity}`,
    setAt: now,
    setBy: 'git-steer-cli-vex-no-fix',
  };
  newVexCount++;
}

cacheJson._vex = existingVex;

console.log(`VEX entries created: ${newVexCount} new (${Object.keys(existingVex).length} total in state)\n`);

// --- Step 5: Persist to state repo ---
console.log('Saving VEX state to git-steer-state repo...');

const content = Buffer.from(JSON.stringify(cacheJson, null, 2)).toString('base64');

try {
  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner,
    repo: STATE_REPO,
    path: 'state/cache.json',
    message: `vex: mark ${newVexCount} alerts as affected (no fix available)`,
    content,
    ...(cacheSha ? { sha: cacheSha } : {}),
  });
  console.log('State saved successfully.\n');
} catch (e) {
  console.error('Failed to save state:', e.message);
  process.exit(1);
}

// --- Step 6: Report what was VEX'd ---
console.log('=== VEX\'D ALERTS (no fix available) ===\n');

const byRepo = {};
for (const alert of noFixAlerts) {
  const key = `${alert.owner}/${alert.repo}`;
  if (!byRepo[key]) byRepo[key] = [];
  byRepo[key].push(alert);
}

for (const [repoName, alerts] of Object.entries(byRepo)) {
  console.log(`${repoName}: ${alerts.length} alert(s) VEX'd`);
  for (const a of alerts) {
    console.log(`  [${a.severity.toUpperCase()}] ${a.package} (${a.cve})`);
  }
  console.log('');
}

// --- Step 7: Rescan summary ---
console.log('=== REMAINING ACTIONABLE ALERTS (have fixes) ===\n');

const fixByRepo = {};
for (const alert of hasFixAlerts) {
  const key = `${alert.owner}/${alert.repo}`;
  if (!fixByRepo[key]) fixByRepo[key] = [];
  fixByRepo[key].push(alert);
}

if (hasFixAlerts.length === 0) {
  console.log('No remaining alerts with available fixes!');
} else {
  for (const [repoName, alerts] of Object.entries(fixByRepo)) {
    console.log(`${repoName}: ${alerts.length} alert(s) with fixes`);
    for (const a of alerts) {
      console.log(`  [${a.severity.toUpperCase()}] ${a.package} → fix: ${a.fixVersion}`);
    }
    console.log('');
  }
}

console.log('=== FINAL SUMMARY ===\n');
console.log(`Total alerts scanned:     ${noFixAlerts.length + hasFixAlerts.length}`);
console.log(`VEX'd (no fix):           ${noFixAlerts.length}`);
console.log(`Remaining (fixable):      ${hasFixAlerts.length}`);
console.log(`New VEX entries created:  ${newVexCount}`);
