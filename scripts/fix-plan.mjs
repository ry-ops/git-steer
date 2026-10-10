/**
 * Fix: the plan (ADR-011). Read-only, through the reporter App.
 *
 * Request forms (issue title): "fix owner/repo", "fix <owner>", "fix fleet",
 * each optionally with "+untested" (include PRs with no checks; the default
 * for a single repo) and "+major" (include major version steps). Fleet and
 * owner scope default to PRs whose checks passed, and use the
 * merge-dependabot-pr-tested change so that rule also holds at merge time.
 *
 * Writes to the working directory:
 *   fix-plan.md        - the reply on the request issue; "{{ROLLOUT}}" stands
 *                        for the rollout issue, which the workflow fills in
 *   rollout-title.txt, rollout-body.md - the merge-dependabot-pr rollout, only
 *                        when there is something to merge
 * On a request it can't serve, it writes fix-plan.md explaining why and exits 1.
 *
 * Refuses to run unless GitHub confirms the running repo is private (C-009-003).
 *
 * Env vars:
 *   REQUEST_TITLE, REQUEST_BODY, REQUEST_ISSUE - the request issue
 *   STARTED_BY                - who opened it
 *   APP_ID, APP_PRIVATE_KEY   - the git-steer-reporter App
 *   GITHUB_TOKEN              - the running repo's token, used only to check it is private
 *   GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID - set by Actions
 */

import { App } from 'octokit';
import { writeFileSync } from 'node:fs';
import { buildFixPlan, buildFleetFixPlan, fleetRolloutTargets, isRunningInPrivateRepo, parseFixRequest, renderFixPlan, renderFleetFixPlan, rolloutTargets } from '../dist/fleet/index.js';
import { CHANGES, renderRolloutIssue } from '../dist/rollout/index.js';

const {
  REQUEST_TITLE = '', REQUEST_BODY = '', REQUEST_ISSUE = '', STARTED_BY = 'unknown',
  APP_ID, APP_PRIVATE_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID,
} = process.env;
const runUrl = GITHUB_SERVER_URL && GITHUB_REPOSITORY && GITHUB_RUN_ID
  ? `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}` : undefined;

function fail(message) {
  console.error(message);
  writeFileSync('fix-plan.md', `## git-steer fix plan: not made\n\n${message}${runUrl ? `\n\n[run](${runUrl})` : ''}\n`);
  process.exit(1);
}

if (!(await isRunningInPrivateRepo(GITHUB_TOKEN, GITHUB_REPOSITORY))) {
  console.error('Refusing to run: a fix plan names a repo and its gaps, so it must run in a private repo (ADR-009 C-009-003).');
  process.exit(1);
}
if (!APP_ID || !APP_PRIVATE_KEY) fail('APP_ID and APP_PRIVATE_KEY are required.');

const request = parseFixRequest(REQUEST_TITLE, REQUEST_BODY);
if (!request) fail('No target found. Ask for `fix owner/repo`, `fix <owner>` or `fix fleet`, optionally with `+untested` and/or `+major`.');
const app = new App({ appId: APP_ID, privateKey: APP_PRIVATE_KEY });
const change = CHANGES[request.opts.untested ? 'merge-dependabot-pr' : 'merge-dependabot-pr-tested'];
const footer = () => `\nFix plan: request #${REQUEST_ISSUE}. Delete the line of any PR you don't want merged before adding \`approved\`.\n`;

if (request.repo) {
  let plan;
  try {
    plan = await buildFixPlan(app, request.repo);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  const { targets, notes } = rolloutTargets(plan, request.opts);
  writeFileSync('fix-plan.md', renderFixPlan(plan, targets.length ? '{{ROLLOUT}}' : undefined, request.opts));
  if (targets.length) {
    const { title, body } = renderRolloutIssue({ change: change.id, summary: change.summary, targets, notes, startedBy: STARTED_BY, runUrl });
    writeFileSync('rollout-title.txt', `${title}: ${request.repo}`);
    writeFileSync('rollout-body.md', body + footer());
  }
  console.log(`${request.repo}: ${plan.prs.length} Dependabot PRs, ${targets.length} on the rollout, ${plan.uncovered.length} alerts with no PR, ${plan.noFix.length} with no fix.`);
} else {
  let fleet;
  try {
    fleet = await buildFleetFixPlan(app, request.owner);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  const { targets, notes, held } = fleetRolloutTargets(fleet, request.opts);
  writeFileSync('fix-plan.md', renderFleetFixPlan(fleet, request.opts, targets.length ? '{{ROLLOUT}}' : undefined, targets.length, held));
  if (targets.length) {
    const { title, body } = renderRolloutIssue({ change: change.id, summary: change.summary, targets, notes, startedBy: STARTED_BY, runUrl });
    writeFileSync('rollout-title.txt', `${title}: ${fleet.scope}`);
    writeFileSync('rollout-body.md', body + footer());
  }
  console.log(`${fleet.scope}: ${fleet.plans.length} repos with Dependabot PRs, ${targets.length} on the rollout, ${held} held by the cap, ${fleet.errors.length} errors.`);
}
