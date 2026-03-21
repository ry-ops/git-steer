#!/usr/bin/env node
/**
 * git-steer web server entry point
 *
 * Lightweight — no Keychain, no keytar, no App auth.
 * Uses GITHUB_TOKEN env var with Octokit directly.
 */

import { TokenGitHubClient } from '../dist/web/github-token.js';
import { startWebServer } from '../dist/web/server.js';

const token = process.env.GITHUB_TOKEN ?? process.env.GIT_STEER_TOKEN ?? '';
const port = parseInt(process.env.PORT ?? '4300', 10);

async function main() {
  console.log('[git-steer-web] Starting...');

  if (!token) {
    console.error('[git-steer-web] GITHUB_TOKEN or GIT_STEER_TOKEN required');
    process.exit(1);
  }

  const github = new TokenGitHubClient(token);

  // Stub state manager — web dashboard uses API calls, not local state
  const state = {
    load: async () => {},
    save: async () => {},
    isDirty: () => false,
    getLastSync: () => null,
    getManagedRepos: () => [],
    getStateRepo: () => process.env.STATE_REPO ?? 'ry-ops/git-steer-state',
    getOwnerName: () => 'ry-ops',
    getRepoName: () => 'git-steer-state',
    getMetrics: () => ({}),
    getRfcs: () => [],
    getQualityResults: () => [],
    getScheduledJobs: () => [],
    getRecentAudit: () => [],
  };

  await startWebServer({ github, state, port, token });
}

main().catch(err => {
  console.error('[git-steer-web] Fatal:', err.message);
  process.exit(1);
});
