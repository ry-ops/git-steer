/**
 * verify-sbom.mjs — exercises the REAL shipped buildSbom (dist/web/routes/sbom.js)
 * against one repo and checks ADR-004 C-004-002 compliance:
 *   - format === 'CycloneDX', valid bomFormat/specVersion
 *   - generatedAt + sourceSha present (sourceSha pinned to a real commit)
 *   - components carry PURLs
 *
 * Usage: node scripts/verify-sbom.mjs [owner/repo]   (default ry-ops/git-steer)
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

console.log(`\n=== SBOM for ${owner}/${repo} ===\n`);
console.log(`format:        ${sbom.format} ${sbom.specVersion}`);
console.log(`generatedAt:   ${sbom.generatedAt}`);
console.log(`sourceSha:     ${sbom.sourceSha}`);
console.log(`components:    ${sbom.componentCount}`);
console.log(`bomFormat:     ${sbom.bom.bomFormat}`);
console.log(`serialNumber:  ${sbom.bom.serialNumber}`);
console.log(`\nsample components:`);
for (const c of sbom.bom.components.slice(0, 5)) {
  console.log(`  ${c.scope.padEnd(8)} ${c.purl}`);
}

const checks = [
  ['format is CycloneDX', sbom.format === 'CycloneDX' && sbom.bom.bomFormat === 'CycloneDX'],
  ['has generatedAt', typeof sbom.generatedAt === 'string' && sbom.generatedAt.length > 0],
  ['has sourceSha (pinned commit)', /^[0-9a-f]{40}$/.test(sbom.sourceSha)],
  ['has components', sbom.componentCount > 0],
  ['all components have PURLs', sbom.bom.components.every((c) => c.purl?.startsWith('pkg:'))],
];

console.log(`\n=== ADR-004 C-004-002 compliance ===`);
let ok = true;
for (const [name, pass] of checks) {
  if (!pass) ok = false;
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}`);
}
console.log(ok ? '\n✅ SBOM is ADR-004 compliant.' : '\n❌ SBOM non-compliant.');
process.exit(ok ? 0 : 1);
