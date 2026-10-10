/**
 * Hand off to Copilot, step 2 (ADR-011): opens the hand-off issues in the one
 * target repo, with a git-steer-admin token minted for that repo with issues:
 * write only (C-010-001). An issue that's already open for the same task (same
 * marker key) is linked, not filed again. Writes handoff-reply.md.
 *
 * Env vars:
 *   GH_TOKEN - git-steer-admin token for the target repo (issues: write)
 * Reads handoff-plan.json from the working directory.
 */

import { Octokit } from 'octokit';
import { readFileSync, writeFileSync } from 'node:fs';
import { markerKey, renderHandoffReply } from '../dist/fleet/index.js';

const { GH_TOKEN } = process.env;
const { owner, name, plan, handoffs, dropped } = JSON.parse(readFileSync('handoff-plan.json', 'utf8'));
const octokit = new Octokit({ auth: GH_TOKEN });

const open = await octokit.paginate('GET /repos/{owner}/{repo}/issues', { owner, repo: name, state: 'open', per_page: 100 });
const existing = new Map();
for (const i of open) {
  const key = i.pull_request ? null : markerKey(i.body ?? '');
  if (key) existing.set(key, i.html_url);
}

const results = [];
for (const h of handoffs) {
  if (existing.has(h.key)) {
    results.push({ key: h.key, title: h.title, url: existing.get(h.key), state: 'already-open' });
    continue;
  }
  try {
    const { data } = await octokit.request('POST /repos/{owner}/{repo}/issues', { owner, repo: name, title: h.title, body: h.body });
    results.push({ key: h.key, title: h.title, url: data.html_url, state: 'opened' });
  } catch (err) {
    results.push({ key: h.key, title: h.title, url: '', state: 'failed', detail: `${err.status ?? ''} ${err.message ?? ''}`.trim() });
  }
}

writeFileSync('handoff-reply.md', renderHandoffReply(plan, results, dropped));
for (const r of results) console.log(`${r.state}: ${r.title} ${r.url}`);
if (results.some((r) => r.state === 'failed')) process.exit(1);
