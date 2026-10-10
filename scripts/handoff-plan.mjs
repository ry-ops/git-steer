/**
 * Hand off to Copilot, step 1 (ADR-011): read-only, through the reporter App.
 *
 * "handoff owner/repo": works out what stands in the way in one repo (its CI,
 * upgrades Dependabot hasn't proposed, packages with no fix).
 * "handoff ci <owner>" / "handoff ci fleet": one CI issue per repo with open
 * Dependabot PRs whose CI is missing or broken.
 *
 * Writes, to the working directory:
 *   handoff-plan.json - HandoffPlanFile: { scope, ci, targets: [{ repo, owner, name, handoffs }], ... }
 *   handoff-reply.md  - only when it stops early, explaining why (exit 1)
 *
 * Refuses to run unless GitHub confirms the running repo is private (C-009-003).
 *
 * Env vars:
 *   REQUEST_TITLE, REQUEST_BODY - the request issue
 *   APP_ID, APP_PRIVATE_KEY     - the git-steer-reporter App
 *   GITHUB_TOKEN                - the running repo's token, used only to check it is private
 *   GITHUB_REPOSITORY - set by Actions
 *
 * The workflow reads each target's owner and name back from handoff-plan.json
 * and checks them before using them as the open job's matrix.
 */

import { App } from 'octokit';
import { writeFileSync } from 'node:fs';
import { buildFixPlan, buildFleetFixPlan, isRunningInPrivateRepo, parseHandoffRequest, planCiHandoffs, planRepoHandoffs } from '../dist/fleet/index.js';

const { REQUEST_TITLE = '', REQUEST_BODY = '', APP_ID, APP_PRIVATE_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY } = process.env;

function fail(message) {
  console.error(message);
  writeFileSync('handoff-reply.md', `## git-steer hand-off: not made\n\n${message}\n`);
  process.exit(1);
}

if (!(await isRunningInPrivateRepo(GITHUB_TOKEN, GITHUB_REPOSITORY))) {
  console.error('Refusing to run: a hand-off plan names a repo and its gaps, so it must run in a private repo (ADR-009 C-009-003).');
  process.exit(1);
}
if (!APP_ID || !APP_PRIVATE_KEY) fail('APP_ID and APP_PRIVATE_KEY are required.');

const request = parseHandoffRequest(REQUEST_TITLE, REQUEST_BODY);
if (!request) fail('No repo found in the request. Name one as `handoff owner/repo`, or ask for `handoff ci <owner>` or `handoff ci fleet`.');

const app = new App({ appId: APP_ID, privateKey: APP_PRIVATE_KEY });
let file;
try {
  if ('repo' in request) {
    file = planRepoHandoffs(await buildFixPlan(app, request.repo));
  } else {
    const fleet = await buildFleetFixPlan(app, request.owner);
    file = planCiHandoffs(fleet.scope, fleet.plans, fleet.errors);
  }
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}

writeFileSync('handoff-plan.json', JSON.stringify(file, null, 2));
const issues = file.targets.reduce((n, t) => n + t.handoffs.length, 0);
console.log(`${file.scope}: ${issues} hand-off issue(s) in ${file.targets.length} repo(s)${file.dropped ? `, ${file.dropped} held back` : ''}.`);
