/**
 * The hourly step's plan (ADR-010). Reads open rollout issues in this repo,
 * checks each was opened by the start workflow and approved by the repo
 * owner (from the issue's label events), and writes the targets for this
 * hour, at most 5, to plan.json as { include: [...] }. The workflow passes
 * it on as the apply job's matrix.
 *
 * Refuses to run outside a private repo: rollout issues name repos (C-009-003).
 *
 * Env vars: GITHUB_TOKEN, GITHUB_REPOSITORY (set by Actions)
 */

import { Octokit } from 'octokit';
import { writeFileSync } from 'node:fs';
import { isRunningInPrivateRepo } from '../dist/fleet/index.js';
import { CHANGES, planStep } from '../dist/rollout/index.js';

const { GITHUB_TOKEN, GITHUB_REPOSITORY = '' } = process.env;
if (!(await isRunningInPrivateRepo(GITHUB_TOKEN, GITHUB_REPOSITORY))) {
  console.error('Refusing to run: rollouts name repos, so they must run in a private repo (ADR-009 C-009-003).');
  process.exit(1);
}
const [owner, repo] = GITHUB_REPOSITORY.split('/');
const octokit = new Octokit({ auth: GITHUB_TOKEN });

const open = await octokit.paginate('GET /repos/{owner}/{repo}/issues', { owner, repo, state: 'open', labels: 'git-steer-rollout', per_page: 100 });
const issues = [];
for (const i of open) {
  const labels = i.labels.map((l) => (typeof l === 'string' ? l : l.name));
  let approvedByOwner = false;
  if (labels.includes('approved')) {
    // The latest `approved` label event must be the owner adding it.
    const events = await octokit.paginate('GET /repos/{owner}/{repo}/issues/{issue_number}/events', { owner, repo, issue_number: i.number, per_page: 100 });
    const last = events.filter((e) => (e.event === 'labeled' || e.event === 'unlabeled') && e.label?.name === 'approved').pop();
    approvedByOwner = last?.event === 'labeled' && last.actor?.login === owner;
  }
  issues.push({ number: i.number, body: i.body ?? '', labels, openedByGitSteer: i.user?.login === 'github-actions[bot]', approvedByOwner });
}

const { items, skipped } = planStep(issues, Object.keys(CHANGES));
for (const s of skipped) console.log(`#${s.issue}: skipped (${s.reason})`);
const matrix = items.map((it, n) => {
  const [o, r] = it.target.split('/');
  return { ...it, owner: o, repo: r ?? '', key: `${n}` };
});
for (const m of matrix) console.log(`#${m.issue}: ${m.change} → ${m.target}`);
writeFileSync('plan.json', JSON.stringify({ include: matrix }));
