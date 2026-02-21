/**
 * CI CVE Queue Compaction
 *
 * Runs in GitHub Actions as part of the heartbeat workflow.
 * Removes resolved CVE queue entries older than the retention period.
 *
 * Env vars:
 *   GH_TOKEN - GitHub installation token
 *   STATE_REPO - State repo name (default: git-steer-state)
 *   STATE_OWNER - State repo owner (default: ry-ops)
 *   RETENTION_DAYS - Days to retain resolved entries (default: 30)
 */

import { Octokit } from 'octokit';

const token = process.env.GH_TOKEN;
if (!token || typeof token !== 'string' || !/^(ghp_|gho_|ghs_|ghu_|github_pat_)[a-zA-Z0-9_]+$/.test(token)) {
  console.error('GH_TOKEN environment variable is required and must be a valid GitHub token');
  process.exit(1);
}

const STATE_OWNER = process.env.STATE_OWNER || 'ry-ops';
const STATE_REPO = process.env.STATE_REPO || 'git-steer-state';
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || '30', 10);
const QUEUE_FILE = 'state/cve-queue.jsonl';

const octokit = new Octokit({ auth: token });

async function main() {
  console.log(`=== CVE Queue Compaction (retention: ${RETENTION_DAYS} days) ===\n`);

  // Read current queue
  let raw = '';
  let sha;
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: QUEUE_FILE }
    );
    raw = Buffer.from(data.content, 'base64').toString('utf8');
    sha = data.sha;
  } catch {
    console.log('No CVE queue file found, nothing to compact.');
    return;
  }

  const entries = raw
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const before = entries.length;
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  const removedByStatus = {};

  const kept = entries.filter((entry) => {
    if (entry.status === 'pending') return true; // never compact pending
    const ts = entry.processedAt || entry.detectedAt;
    if (ts && new Date(ts).getTime() < cutoff) {
      removedByStatus[entry.status] = (removedByStatus[entry.status] || 0) + 1;
      return false;
    }
    return true;
  });

  const removed = before - kept.length;

  if (removed === 0) {
    console.log(`Queue has ${before} entries, nothing to compact.`);
    return;
  }

  // Write compacted queue
  const content = kept.map((e) => JSON.stringify(e)).join('\n') + '\n';
  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner: STATE_OWNER,
    repo: STATE_REPO,
    path: QUEUE_FILE,
    message: `chore(cve): compact queue — removed ${removed} resolved entries`,
    content: Buffer.from(content).toString('base64'),
    sha,
    branch: 'main',
  });

  console.log(`Compacted: ${before} → ${kept.length} (removed ${removed})`);
  for (const [status, count] of Object.entries(removedByStatus)) {
    console.log(`  ${status}: ${count} removed`);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
