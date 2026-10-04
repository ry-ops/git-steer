/**
 * The hourly step's plan (ADR-010). Reads open rollout issues in this repo,
 * checks each was opened by the start workflow and approved by the repo
 * owner (from the issue's label events), and writes the targets for this
 * hour to plan.json as { include: [...] }. The hour's budget is 5 minus the
 * writes already recorded on rollout issues in the last 60 minutes, so a
 * late or manual run can't exceed 5 an hour (C-010-003). The workflow passes
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

// Open rollouts can be worked; recently closed ones only count toward the hour's writes.
const since = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
const listed = await octokit.paginate('GET /repos/{owner}/{repo}/issues', { owner, repo, state: 'all', labels: 'git-steer-rollout', since, per_page: 100 });
const openOnes = await octokit.paginate('GET /repos/{owner}/{repo}/issues', { owner, repo, state: 'open', labels: 'git-steer-rollout', per_page: 100 });
const byNumber = new Map([...listed, ...openOnes].map((i) => [i.number, i]));
const issues = [];
for (const i of byNumber.values()) {
  const labels = i.labels.map((l) => (typeof l === 'string' ? l : l.name));
  let approvedByOwner = false;
  if (i.state === 'open' && labels.includes('approved')) {
    // The latest `approved` label event must be the owner adding it.
    const events = await octokit.paginate('GET /repos/{owner}/{repo}/issues/{issue_number}/events', { owner, repo, issue_number: i.number, per_page: 100 });
    const last = events.filter((e) => (e.event === 'labeled' || e.event === 'unlabeled') && e.label?.name === 'approved').pop();
    approvedByOwner = last?.event === 'labeled' && last.actor?.login === owner;
  }
  issues.push({ number: i.number, open: i.state === 'open', body: i.body ?? '', labels, openedByGitSteer: i.user?.login === 'github-actions[bot]', approvedByOwner });
}

const { items, skipped, recent, budget } = planStep(issues, Object.keys(CHANGES));
console.log(`Writes in the last hour: ${recent}. Budget now: ${budget}.`);
for (const s of skipped) console.log(`#${s.issue}: skipped (${s.reason})`);
const matrix = items.map((it, n) => {
  const [o, r] = it.target.split('/');
  return { ...it, owner: o, repo: r ?? '', key: `${n}` };
});
for (const m of matrix) console.log(`#${m.issue}: ${m.change} → ${m.target}`);
writeFileSync('plan.json', JSON.stringify({ include: matrix }));
