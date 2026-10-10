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
 * Reads handoff-plan.json; writes handoff-result.json (uploaded under a per-repo artifact name).
 */

import { Octokit } from 'octokit';
import { readFileSync, writeFileSync } from 'node:fs';
import { markerKey } from '../dist/fleet/index.js';

const { GH_TOKEN, TARGET_OWNER, TARGET_NAME } = process.env;
const plan = JSON.parse(readFileSync('handoff-plan.json', 'utf8'));
const octokit = new Octokit({ auth: GH_TOKEN });

// The plan's entry for this job's repo: the issues opened are only ever the
// plan's own. A repo not in the plan opens nothing.
const results = [];
for (const { owner, name, repo, handoffs } of plan.targets.filter((t) => t.owner === TARGET_OWNER && t.name === TARGET_NAME)) {
  const open = await octokit.paginate('GET /repos/{owner}/{repo}/issues', { owner, repo: name, state: 'open', per_page: 100 });
  const existing = new Map();
  for (const i of open) {
    const key = i.pull_request ? null : markerKey(i.body ?? '');
    if (key) existing.set(key, i.html_url);
  }
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
}

writeFileSync('handoff-result.json', JSON.stringify(results, null, 2));
for (const r of results) console.log(`${r.state}: ${r.title} ${r.url}`);
if (!results.length) console.log('Nothing in the plan for this repo.');
if (results.some((r) => r.state === 'failed')) process.exit(1);
