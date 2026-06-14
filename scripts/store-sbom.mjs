/**
 * store-sbom.mjs — build a CycloneDX SBOM for a repo and persist it to the
 * git-steer-state repo at sbom/<owner>__<repo>.cdx.json (ADR-004 C-004-002).
 *
 * Build first: `npm run build`.
 * Usage: node scripts/store-sbom.mjs [owner/repo]   (default ry-ops/git-steer)
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { buildSbom } from '../dist/web/routes/sbom.js';

const target = process.argv[2] || 'ry-ops/git-steer';
const [owner, repo] = target.split('/');

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

const sbom = await buildSbom(octokit, owner, repo);
console.log(`Built CycloneDX SBOM for ${target}: ${sbom.componentCount} components @ ${sbom.sourceSha.slice(0, 12)}`);

const STATE_REPO = 'git-steer-state';
const path = `sbom/${owner}__${repo}.cdx.json`;
const content = Buffer.from(JSON.stringify(sbom, null, 2)).toString('base64');

let sha;
try {
  const { data: existing } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
    owner, repo: STATE_REPO, path,
  });
  sha = existing.sha;
} catch { /* first write */ }

await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner, repo: STATE_REPO, path,
  message: `sbom: ${target} — ${sbom.componentCount} components @ ${sbom.sourceSha.slice(0, 12)}`,
  content,
  ...(sha ? { sha } : {}),
});

console.log(`Stored → ${STATE_REPO}/${path}`);
