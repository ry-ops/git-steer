/**
 * verify-app-scan.mjs — exercises the REAL shipped app code path
 * (dist/web/github-token.js → TokenGitHubClient.getSecurityAlertsDetailed)
 * against a single repo, using a minted installation token.
 *
 * Confirms the canonical scanner (not a copy) now reports ALL issues:
 * dependabot + code-scanning, fully paginated.
 *
 * Usage: node scripts/verify-app-scan.mjs [owner/repo]   (default ry-ops/git-steer)
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { TokenGitHubClient } from '../dist/web/github-token.js';

const target = process.argv[2] || 'ry-ops/git-steer';
const [owner, repo] = target.split('/');

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

// Mint a real installation access token (App JWT → installation token)
const app = new App({ appId, privateKey });
const { data: tok } = await app.octokit.request(
  'POST /app/installations/{installation_id}/access_tokens',
  { installation_id: Number(installationId) },
);

// Drive the actual shipped client
const client = new TokenGitHubClient(tok.token);
const alerts = await client.getSecurityAlertsDetailed(owner, repo);

const by = (pred) => alerts.filter(pred);
const sevRollup = (items) => {
  const c = {};
  for (const a of items) c[a.severity] = (c[a.severity] || 0) + 1;
  return Object.entries(c).map(([s, n]) => `${s}:${n}`).join('  ') || '(none)';
};

const dep = by((a) => a.source === 'dependabot');
const scan = by((a) => a.source === 'code-scanning');

console.log(`\n=== Shipped TokenGitHubClient.getSecurityAlertsDetailed(${owner}/${repo}) ===\n`);
console.log(`source=dependabot:    ${dep.length}   ${sevRollup(dep)}`);
console.log(`source=code-scanning: ${scan.length}   ${sevRollup(scan)}`);
console.log(`\nTOTAL returned by app: ${alerts.length}   ${sevRollup(alerts)}`);

// Cross-check against independent gh-derived ground truth passed via env
const expected = Number(process.env.EXPECT_TOTAL || '0');
if (expected) {
  const pass = alerts.length === expected;
  console.log(`\n${pass ? '✅ PASS' : '❌ FAIL'}  app=${alerts.length}  expected=${expected}`);
  process.exit(pass ? 0 : 1);
}
