/**
 * Single-repo scan (ADR-009 Layer 2, one repo).
 *
 * Reads one repo through the read-only reporter App and writes scan.md (the
 * issue comment) and scan.json to the working directory. Posting the comment
 * is the workflow's job, with the fleet repo's own GITHUB_TOKEN. On a request
 * it can't serve, it still writes scan.md explaining why, and exits 1.
 *
 * Refuses to run unless GitHub confirms the running repo is private
 * (C-009-003). Needs `npm run build` first.
 *
 * Env vars:
 *   REQUEST                   - text naming the repo: "scan owner/repo", or a github.com URL
 *   APP_ID, APP_PRIVATE_KEY   - the git-steer-reporter App
 *   GITHUB_TOKEN              - the running repo's token, used only to check it is private
 *   GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID - set by Actions
 */

import { App } from 'octokit';
import { writeFileSync } from 'node:fs';
import { isRunningInPrivateRepo, parseScanTarget, renderScan, scanRepo } from '../dist/fleet/index.js';

const { REQUEST = '', APP_ID, APP_PRIVATE_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID } = process.env;
const runUrl = GITHUB_SERVER_URL && GITHUB_REPOSITORY && GITHUB_RUN_ID
  ? `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}` : undefined;

function fail(message) {
  console.error(message);
  writeFileSync('scan.md', `## git-steer scan: not run\n\n${message}${runUrl ? `\n\n[run](${runUrl})` : ''}\n`);
  process.exit(1);
}

if (!(await isRunningInPrivateRepo(GITHUB_TOKEN, GITHUB_REPOSITORY))) {
  console.error('Refusing to run: a scan names a repo and its gaps, so it must run in a private repo (ADR-009 C-009-003).');
  process.exit(1);
}
if (!APP_ID || !APP_PRIVATE_KEY) fail('APP_ID and APP_PRIVATE_KEY are required.');

const target = parseScanTarget(REQUEST);
if (!target) fail('No repo found in the request. Name one as `scan owner/repo`.');

let scan;
try {
  scan = await scanRepo(new App({ appId: APP_ID, privateKey: APP_PRIVATE_KEY }), target);
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}
scan.runUrl = runUrl;

writeFileSync('scan.json', JSON.stringify(scan, null, 2));
writeFileSync('scan.md', renderScan(scan));
console.log(`Scanned ${target}: ${scan.alerts === null ? 'Dependabot alerts unknown' : `${scan.alerts.length} open Dependabot alerts`}.`);
