/**
 * Hand off to Copilot, step 1 (ADR-011): read-only, through the reporter App.
 *
 * Works out what Dependabot can't fix in one repo and writes, to the working
 * directory:
 *   handoff-plan.json - { repo, owner, name, plan, handoffs, dropped }
 *   handoff-reply.md  - only when it stops early, explaining why (exit 1)
 *
 * Refuses to run unless GitHub confirms the running repo is private (C-009-003).
 *
 * Env vars:
 *   REQUEST_TITLE, REQUEST_BODY - the request issue
 *   APP_ID, APP_PRIVATE_KEY     - the git-steer-reporter App
 *   GITHUB_TOKEN                - the running repo's token, used only to check it is private
 *   GITHUB_REPOSITORY, GITHUB_OUTPUT - set by Actions
 */

import { App } from 'octokit';
import { appendFileSync, writeFileSync } from 'node:fs';
import { buildFixPlan, buildHandoffs, isRunningInPrivateRepo, parseScanTarget } from '../dist/fleet/index.js';

const { REQUEST_TITLE = '', REQUEST_BODY = '', APP_ID, APP_PRIVATE_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_OUTPUT } = process.env;

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

const target = parseScanTarget(`${REQUEST_TITLE}\n${REQUEST_BODY}`);
if (!target) fail('No repo found in the request. Name one as `handoff owner/repo`.');

let plan;
try {
  plan = await buildFixPlan(new App({ appId: APP_ID, privateKey: APP_PRIVATE_KEY }), target);
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}

const [owner, name] = target.split('/');
const handoffs = buildHandoffs(plan); // at most MAX_HANDOFFS
const wanted = new Set(plan.noFix.map((a) => a.package)).size + (plan.uncovered.length ? 1 : 0);
const dropped = Math.max(0, wanted - handoffs.length);
writeFileSync('handoff-plan.json', JSON.stringify({ repo: target, owner, name, plan, handoffs, dropped }, null, 2));
if (GITHUB_OUTPUT) appendFileSync(GITHUB_OUTPUT, `owner=${owner}\nname=${name}\ncount=${handoffs.length}\n`);
console.log(`${target}: ${handoffs.length} hand-off issue(s)${dropped ? `, ${dropped} held back` : ''}.`);
