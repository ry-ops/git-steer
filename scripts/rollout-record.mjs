/**
 * Records the hour's results on their rollout issues (ADR-010, C-010-007):
 * ticks each box, labels the rollout `paused` on a failure (C-010-004), and
 * closes it when every target is done.
 *
 * Env vars:
 *   GITHUB_TOKEN, GITHUB_REPOSITORY - this repo's token (issues: write)
 *   RESULTS_DIR                     - directory holding result.json files
 */

import { Octokit } from 'octokit';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parseRolloutIssue, recordResult, remaining } from '../dist/rollout/index.js';

const { GITHUB_TOKEN, GITHUB_REPOSITORY = '', RESULTS_DIR = 'results' } = process.env;
const [owner, repo] = GITHUB_REPOSITORY.split('/');
const octokit = new Octokit({ auth: GITHUB_TOKEN });

const files = [];
(function walk(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (f === 'result.json') files.push(p);
  }
})(RESULTS_DIR);

const byIssue = new Map();
for (const f of files) {
  const r = JSON.parse(readFileSync(f, 'utf8'));
  if (!byIssue.has(r.issue)) byIssue.set(r.issue, []);
  byIssue.get(r.issue).push(r);
}

for (const [issue_number, results] of byIssue) {
  const { data: issue } = await octokit.request('GET /repos/{owner}/{repo}/issues/{issue_number}', { owner, repo, issue_number });
  let body = issue.body ?? '';
  for (const r of results.sort((a, b) => a.at.localeCompare(b.at))) body = recordResult(body, r);
  await octokit.request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', { owner, repo, issue_number, body });

  const failed = results.filter((r) => r.outcome === 'failed');
  if (failed.length) {
    await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', { owner, repo, issue_number, labels: ['paused'] });
    await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
      owner, repo, issue_number,
      body: `⏸️ Paused: ${failed.map((r) => `\`${r.target}\` (${r.after})`).join(', ')}. Fix the cause, then remove the \`paused\` label to retry (ADR-010 C-010-004).`,
    });
  }
  const rollout = parseRolloutIssue(body);
  if (rollout && remaining(rollout).length === 0) {
    await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', { owner, repo, issue_number, body: '✅ Rollout complete: every target is done.' });
    await octokit.request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', { owner, repo, issue_number, state: 'closed', state_reason: 'completed' });
  }
  console.log(`#${issue_number}: recorded ${results.length} result(s)${failed.length ? `, paused (${failed.length} failed)` : ''}`);
}
