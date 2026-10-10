/**
 * Hand off to Copilot, step 2 (ADR-011): opens one target repo's hand-off
 * issues, with a git-steer-admin token minted for that repo with issues:
 * write only (C-010-001). The workflow runs this once per target repo. An
 * issue that's already open for the same task (same marker key) is linked,
 * not filed again.
 *
 * Env vars:
 *   GH_TOKEN                   - git-steer-admin token for the target repo (issues: write)
 *   TARGET_OWNER, TARGET_NAME  - the target repo (one entry of the plan)
 * Reads handoff-plan.json; writes handoff-result-<owner>-<name>.json.
 */

import { Octokit } from 'octokit';
import { readFileSync, writeFileSync } from 'node:fs';
import { markerKey } from '../dist/fleet/index.js';

const { GH_TOKEN, TARGET_OWNER, TARGET_NAME } = process.env;
const plan = JSON.parse(readFileSync('handoff-plan.json', 'utf8'));
const target = plan.targets.find((t) => t.owner === TARGET_OWNER && t.name === TARGET_NAME);
if (!target) {
  console.error(`${TARGET_OWNER}/${TARGET_NAME} isn't in the plan.`);
  process.exit(1);
}
const { owner, name, repo, handoffs } = target;
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
    results.push({ repo, key: h.key, title: h.title, url: existing.get(h.key), state: 'already-open' });
    continue;
  }
  try {
    const { data } = await octokit.request('POST /repos/{owner}/{repo}/issues', { owner, repo: name, title: h.title, body: h.body });
    results.push({ repo, key: h.key, title: h.title, url: data.html_url, state: 'opened' });
  } catch (err) {
    results.push({ repo, key: h.key, title: h.title, url: '', state: 'failed', detail: `${err.status ?? ''} ${err.message ?? ''}`.trim() });
  }
}

writeFileSync(`handoff-result-${owner}-${name}.json`, JSON.stringify(results, null, 2));
for (const r of results) console.log(`${r.state}: ${r.title} ${r.url}`);
if (results.some((r) => r.state === 'failed')) process.exit(1);
