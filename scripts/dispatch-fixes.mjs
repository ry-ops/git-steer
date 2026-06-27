/**
 * Dispatch security-fix-worker workflow for all repos with fixable alerts.
 * Runs all dispatches in parallel.
 */

import keytar from 'keytar';
import { App } from 'octokit';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// Repos with fixable alerts from our scan
const targetRepos = [
  'ry-ops/unifi-cloudflare-ddns',
  'ry-ops/aiana',
  'ry-ops/ATSFlow',
  'ry-ops/DriveIQ',
  // ry-ops/blog removed: transferred to fabric-forge/blog and dropped from the
  // managed fleet — remediation for it is intentionally skipped.
  'ry-ops/building-serverless-website-github-cloudflare',
  'ry-ops/getting-started-docker-containers',
  'ry-ops/building-rest-api-fastapi',
  'ry-ops/qdrant-fabric',
  'ry-ops/homelab-hub-plus',
];

console.log(`Dispatching security-fix-worker for ${targetRepos.length} repos...\n`);

const results = await Promise.allSettled(
  targetRepos.map(async (repo) => {
    const jobId = `fix-${repo.split('/')[1]}-${Date.now()}`;
    await octokit.request(
      'POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches',
      {
        owner: 'ry-ops',
        repo: 'git-steer',
        workflow_id: 'security-fix-worker.yml',
        ref: 'main',
        inputs: {
          target_repo: repo,
          severity: 'low',
          dry_run: 'false',
          job_id: jobId,
        },
      }
    );
    return { repo, jobId };
  })
);

console.log('=== DISPATCH RESULTS ===\n');

let success = 0;
let failed = 0;

for (const result of results) {
  if (result.status === 'fulfilled') {
    console.log(`  [OK] ${result.value.repo} (job: ${result.value.jobId})`);
    success++;
  } else {
    const reason = result.reason?.message || result.reason;
    // Try to identify which repo failed
    console.log(`  [FAIL] ${reason}`);
    failed++;
  }
}

console.log(`\nDispatched: ${success} | Failed: ${failed}`);
console.log('\nWorkflows are running on GitHub Actions. Monitor at:');
console.log('  https://github.com/ry-ops/git-steer/actions/workflows/security-fix-worker.yml');
