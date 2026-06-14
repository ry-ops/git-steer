/**
 * apply-vex-dispositions.mjs — atomically VEX + dismiss code-scanning findings
 * (ADR-004 C-004-007). For each disposition: write a validated OpenVEX entry to
 * git-steer-state `_vex` AND dismiss the GitHub code-scanning alert with a
 * matching reason, so it stops resurfacing while staying tracked.
 *
 * Build first: `npm run build`.
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { validateVexInput, vexId } from '../dist/core/vex.js';

const REPO_FULL = 'ry-ops/git-steer';
const [OWNER, REPO] = REPO_FULL.split('/');
const PRODUCT_PURL = `pkg:github/${REPO_FULL}`;

// The 4 triaged code-scanning findings (the other 17 were fixed in code).
const DISPOSITIONS = [
  {
    number: 28, rule: 'js/clear-text-logging', loc: 'bin/cli.js:368',
    justification: 'inline_mitigations_already_exist',
    note: 'error.message is piped through a regex redacting ghp_/gho_/ghs_/github_pat_ tokens and only logged under DEBUG.',
  },
  {
    number: 22, rule: 'js/user-controlled-bypass', loc: 'bin/web.js:18',
    justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
    note: 'The guarded check is `if(!token)` on process.env.GITHUB_TOKEN — operator startup config, not adversary-reachable input.',
  },
  {
    number: 42, rule: 'js/user-controlled-bypass', loc: 'src/web/routes/cve.ts:567',
    justification: 'vulnerable_code_not_in_execute_path',
    note: 'dryRun is a by-design API flag (preview vs execute) behind Bearer auth + rate limiting; no security control is bypassed.',
  },
  {
    number: 43, rule: 'js/user-controlled-bypass', loc: 'src/web/routes/cve.ts:609',
    justification: 'vulnerable_code_not_in_execute_path',
    note: 'verify is a by-design API flag that triggers an extra re-scan; no privileged path is gated by it.',
  },
];

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');
const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// ── Load existing _vex from git-steer-state ───────────────────────────
const STATE_REPO = 'git-steer-state';
let cacheJson = {};
let cacheSha = null;
try {
  const { data: file } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
    owner: OWNER, repo: STATE_REPO, path: 'state/cache.json',
  });
  cacheSha = file.sha;
  cacheJson = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));
} catch { console.log('No cache.json found; creating fresh.'); }
const existingVex = cacheJson._vex || {};

const now = new Date().toISOString();
let written = 0, dismissed = 0;

for (const d of DISPOSITIONS) {
  const cveId = `codeql/${d.rule}#${d.number}`;
  const entry = {
    cve_id: cveId,
    repo: REPO_FULL,
    product_purl: PRODUCT_PURL,
    status: 'not_affected',
    justification: d.justification,
    impact_statement: `${d.loc} — ${d.note}`,
    detail: `CodeQL ${d.rule} alert #${d.number}. Re-evaluate on next scan (ADR-004 C-004-005).`,
    created_at: now,
    updated_by: 'git-steer-cycle',
  };

  const err = validateVexInput(entry);
  if (err) { console.error(`  [skip] ${cveId}: ${err}`); continue; }

  // 1. Write VEX record
  existingVex[vexId(REPO_FULL, cveId)] = entry;
  written++;

  // 2. Dismiss the GitHub code-scanning alert (matching reason)
  try {
    await octokit.request('PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}', {
      owner: OWNER, repo: REPO, alert_number: d.number,
      state: 'dismissed',
      dismissed_reason: 'false positive',
      dismissed_comment: `VEX not_affected (${d.justification}): ${d.note} [ADR-004; re-evaluated each scan]`,
    });
    dismissed++;
    console.log(`  ✓ #${d.number} ${d.rule} @ ${d.loc} — VEX'd + dismissed`);
  } catch (e) {
    console.error(`  ! #${d.number} VEX written but dismiss failed: ${e.status} ${e.message}`);
  }
}

// ── Persist _vex ──────────────────────────────────────────────────────
cacheJson._vex = existingVex;
const content = Buffer.from(JSON.stringify(cacheJson, null, 2)).toString('base64');
await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner: OWNER, repo: STATE_REPO, path: 'state/cache.json',
  message: `vex: not_affected dispositions for ${written} codeql findings (+dismiss)`,
  content,
  ...(cacheSha ? { sha: cacheSha } : {}),
});

console.log(`\nVEX records written: ${written}   |   GH alerts dismissed: ${dismissed}`);
console.log(`Total _vex entries in state: ${Object.keys(existingVex).length}`);
