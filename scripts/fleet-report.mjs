/**
 * Fleet report (ADR-009 Layer 2)
 *
 * Reads the whole fleet through the read-only reporter App and writes:
 *   status.json   - fleet status (src/fleet/types.ts, schema git-steer/fleet-status@2)
 *   dashboard.md  - the dashboard issue body
 * to the working directory. Updating the issue is the workflow's job, with
 * the fleet repo's own GITHUB_TOKEN.
 *
 * Refuses to run unless GitHub confirms the running repo is private
 * (C-009-003). Needs `npm run build` first.
 *
 * Env vars:
 *   APP_ID, APP_PRIVATE_KEY   - the git-steer-reporter App
 *   GITHUB_TOKEN              - the running repo's token, used only to check it is private
 *   GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID - set by Actions
 */

import { App } from 'octokit';
import { writeFileSync } from 'node:fs';
import { collectFleet, isRunningInPrivateRepo, renderDashboard, decisionCounts } from '../dist/fleet/index.js';

const { APP_ID, APP_PRIVATE_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID } = process.env;

if (!(await isRunningInPrivateRepo(GITHUB_TOKEN, GITHUB_REPOSITORY))) {
  console.error('Refusing to run: the fleet report names repos and their gaps, so it must run in a private repo (ADR-009 C-009-003).');
  process.exit(1);
}
if (!APP_ID || !APP_PRIVATE_KEY) {
  console.error('APP_ID and APP_PRIVATE_KEY are required.');
  process.exit(1);
}

const app = new App({ appId: APP_ID, privateKey: APP_PRIVATE_KEY });
const status = await collectFleet(app);
if (GITHUB_SERVER_URL && GITHUB_REPOSITORY && GITHUB_RUN_ID) {
  status.runUrl = `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}`;
}

writeFileSync('status.json', JSON.stringify(status, null, 2));
writeFileSync('dashboard.md', renderDashboard(status));

const d = decisionCounts(status);
console.log(`Fleet: ${status.repos.length} repos across ${status.owners.length} owners.`);
console.log(`Needs you: ${d.noPatch} alerts without a fix, ${d.stalePrs} stale Dependabot PRs, ${d.undocumentedDismissals} undocumented dismissals, ${d.settingsOff} repos with settings off, ${d.unprotected} unprotected.`);
console.log(`Couldn't fully read: ${d.unknown} repos.`);
