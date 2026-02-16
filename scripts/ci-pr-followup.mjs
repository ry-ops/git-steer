/**
 * CI PR Follow-up
 *
 * Runs in GitHub Actions (daily via heartbeat, before dashboard).
 * Closes the PR lifecycle loop:
 *   - Checks status of security PRs linked to RFCs
 *   - Marks merged PRs as fixed, computes MTTR
 *   - Nudges stale PRs (>48h open)
 *   - Flags merge conflicts
 *   - Resets RFCs when PRs are closed without merge
 *   - Catches orphaned security PRs not linked to RFCs
 *
 * Env vars:
 *   GH_TOKEN     - GitHub installation token
 *   STATE_OWNER  - State repo owner (default: ry-ops)
 *   STATE_REPO   - State repo name (default: git-steer-state)
 */

import { Octokit } from 'octokit';

const token = process.env.GH_TOKEN;
if (!token) {
  console.error('GH_TOKEN environment variable is required');
  process.exit(1);
}

const STATE_OWNER = process.env.STATE_OWNER || 'ry-ops';
const STATE_REPO = process.env.STATE_REPO || 'git-steer-state';
const STALE_HOURS = 48;
const ORPHAN_HOURS = 24;

const octokit = new Octokit({ auth: token });

// ===== Load RFCs from state repo =====
async function loadRfcs() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/rfcs.jsonl' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    return {
      rfcs: content.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l)),
      sha: data.sha,
    };
  } catch {
    return { rfcs: [], sha: null };
  }
}

// ===== Save RFCs back to state repo =====
async function saveRfcs(rfcs, sha) {
  const content = rfcs.map((r) => JSON.stringify(r)).join('\n') + '\n';
  const params = {
    owner: STATE_OWNER,
    repo: STATE_REPO,
    path: 'state/rfcs.jsonl',
    message: `state: PR follow-up ${new Date().toISOString().split('T')[0]}`,
    content: Buffer.from(content).toString('base64'),
  };
  if (sha) params.sha = sha;

  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', params);
}

// ===== Fetch managed repos =====
async function getManagedRepos() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'config/managed-repos.yaml' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    const repos = content.match(/^\s*-\s+(.+)$/gm);
    if (repos) {
      return repos.map((r) => {
        const name = r.replace(/^\s*-\s+/, '').trim();
        const [owner, repo] = name.split('/');
        return { owner, name: repo, fullName: name };
      });
    }
  } catch {
    // fallback
  }

  const { data } = await octokit.request('GET /installation/repositories');
  return data.repositories
    .filter((r) => !r.archived)
    .map((r) => ({ owner: r.owner.login, name: r.name, fullName: r.full_name }));
}

// ===== Main =====
async function main() {
  console.log('=== git-steer PR Follow-up ===\n');

  const { rfcs, sha } = await loadRfcs();
  console.log(`Loaded ${rfcs.length} RFCs\n`);

  const now = Date.now();
  let updated = 0;
  let staleNudged = 0;
  let fixed = 0;
  let conflicts = 0;
  let reopened = 0;
  let orphansWarned = 0;

  // Process RFCs with open/in_progress status
  const activeRfcs = rfcs.filter((r) => r.status === 'open' || r.status === 'in_progress');
  console.log(`Active RFCs: ${activeRfcs.length}\n`);

  for (const rfc of activeRfcs) {
    const [owner, repo] = (rfc.repo || '').split('/');
    if (!owner || !repo) continue;

    if (rfc.prNumber) {
      // Fetch PR status
      try {
        const { data: pr } = await octokit.request(
          'GET /repos/{owner}/{repo}/pulls/{pull_number}',
          { owner, repo, pull_number: rfc.prNumber }
        );

        if (pr.merged) {
          // PR merged — mark RFC as fixed
          rfc.status = 'fixed';
          rfc.fixedAt = pr.merged_at;
          if (rfc.ts) {
            rfc.mttr = Math.round((new Date(pr.merged_at) - new Date(rfc.ts)) / 3600000);
          }
          updated++;
          fixed++;
          console.log(`  ${rfc.repo} RFC #${rfc.issueNumber}: FIXED (PR #${rfc.prNumber} merged, MTTR: ${rfc.mttr || '?'}h)`);

          // Close the RFC issue
          if (rfc.issueNumber && rfc.issueNumber > 0) {
            try {
              await octokit.request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                owner, repo,
                issue_number: rfc.issueNumber,
                state: 'closed',
                state_reason: 'completed',
              });
              await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                owner, repo,
                issue_number: rfc.issueNumber,
                body: `## Resolved\n\nFix PR #${rfc.prNumber} has been merged.\nMTTR: **${rfc.mttr || '?'} hours**\n\n_Closed by git-steer PR follow-up._`,
              });
            } catch (err) {
              console.error(`    Warning: could not close issue #${rfc.issueNumber}: ${err.message}`);
            }
          }

        } else if (pr.state === 'closed') {
          // PR closed without merge — reset RFC to open
          rfc.status = 'open';
          delete rfc.prNumber;
          delete rfc.prUrl;
          updated++;
          reopened++;
          console.log(`  ${rfc.repo} RFC #${rfc.issueNumber}: REOPENED (PR was closed without merge)`);

        } else {
          // PR still open — check for staleness and conflicts
          const prAgeHours = (now - new Date(pr.updated_at).getTime()) / 3600000;

          if (pr.mergeable === false) {
            // Merge conflict
            conflicts++;
            updated++;
            console.log(`  ${rfc.repo} PR #${rfc.prNumber}: MERGE CONFLICT`);
            try {
              await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                owner, repo,
                issue_number: rfc.prNumber,
                body: `## Merge Conflict Detected\n\nThis PR has merge conflicts that need to be resolved before it can be merged.\n\n_Flagged by git-steer PR follow-up._`,
              });
              // Add label
              await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
                owner, repo,
                issue_number: rfc.prNumber,
                labels: ['merge-conflict'],
              });
            } catch (err) {
              console.error(`    Warning: could not comment on PR #${rfc.prNumber}: ${err.message}`);
            }

          } else if (prAgeHours > STALE_HOURS) {
            // Stale PR
            staleNudged++;
            updated++;
            console.log(`  ${rfc.repo} PR #${rfc.prNumber}: STALE (${Math.round(prAgeHours)}h since last update)`);
            try {
              await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
                owner, repo,
                issue_number: rfc.prNumber,
                body: `## Review Needed\n\nThis security fix PR has been open for **${Math.round(prAgeHours)} hours** without updates. Please review and merge to close the vulnerability window.\n\n_Nudge from git-steer PR follow-up._`,
              });
              await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
                owner, repo,
                issue_number: rfc.prNumber,
                labels: ['stale'],
              });
            } catch (err) {
              console.error(`    Warning: could not nudge PR #${rfc.prNumber}: ${err.message}`);
            }
          }
        }
      } catch (err) {
        console.error(`  ${rfc.repo} PR #${rfc.prNumber}: ERROR fetching PR: ${err.message}`);
      }

    } else {
      // No PR linked — warn if RFC is old
      const rfcAgeHours = rfc.ts ? (now - new Date(rfc.ts).getTime()) / 3600000 : 0;
      if (rfcAgeHours > ORPHAN_HOURS) {
        orphansWarned++;
        console.log(`  ${rfc.repo} RFC #${rfc.issueNumber}: WARNING — no PR after ${Math.round(rfcAgeHours)}h (workflow may have failed)`);
      }
    }
  }

  // Fallback: scan for open security PRs not linked to any RFC
  console.log('\nScanning for orphaned security PRs...');
  const managedRepos = await getManagedRepos();
  let orphanPRs = 0;

  for (const repo of managedRepos) {
    try {
      const { data: prs } = await octokit.request('GET /repos/{owner}/{repo}/pulls', {
        owner: repo.owner,
        repo: repo.name,
        state: 'open',
        per_page: 20,
      });

      for (const pr of prs) {
        const labels = pr.labels.map((l) => l.name);
        if (labels.includes('security') && labels.includes('automated')) {
          // Check if this PR is already tracked by an RFC
          const tracked = rfcs.some((r) => r.prNumber === pr.number && r.repo === repo.fullName);
          if (!tracked) {
            orphanPRs++;
            console.log(`  ${repo.fullName} PR #${pr.number}: orphaned security PR (not linked to RFC)`);
          }
        }
      }
    } catch {
      // Skip repos we can't access
    }
  }

  // Save updated RFCs
  if (updated > 0) {
    console.log(`\nSaving ${updated} RFC updates...`);
    await saveRfcs(rfcs, sha);
  }

  // Print summary
  console.log('\n=== Summary ===');
  console.log(`  Fixed (merged):    ${fixed}`);
  console.log(`  Stale (nudged):    ${staleNudged}`);
  console.log(`  Merge conflicts:   ${conflicts}`);
  console.log(`  Reopened:          ${reopened}`);
  console.log(`  Orphan warnings:   ${orphansWarned}`);
  console.log(`  Orphan PRs found:  ${orphanPRs}`);
  console.log(`  Total updated:     ${updated}`);
  console.log('\nDone!');
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
