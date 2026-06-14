/**
 * dismiss-codeql-fp.mjs — VEX + dismiss a class of CodeQL findings that are
 * mitigated but not recognized by the analyzer (ADR-004 C-004-007).
 *
 * Configured here for js/missing-rate-limiting: every web route is rate-limited
 * by the global @fastify/rate-limit registration (src/web/server.ts), but
 * CodeQL's js/missing-rate-limiting does not recognize global fastify plugins,
 * so it flags each handler. Disposition: not_affected / inline_mitigations_
 * already_exist, dismissed with a matching reason, recorded in the VEX ledger.
 *
 * Build first: `npm run build`.
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { validateVexInput, vexId, makeVexLedgerEntry } from '../dist/core/vex.js';
import { appendJsonl } from './lib/state-jsonl.mjs';

const REPO_FULL = 'ry-ops/git-steer';
const [OWNER, REPO] = REPO_FULL.split('/');
const RULE = 'js/missing-rate-limiting';
const JUSTIFICATION = 'inline_mitigations_already_exist';
const NOTE = 'All web routes are rate-limited by a global @fastify/rate-limit registration (src/web/server.ts). CodeQL does not recognize global fastify plugins, so each handler is flagged despite the runtime limiter.';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');
const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// Find open alerts for the rule (optional --ref to catch PR-head instances)
const refArg = process.argv.indexOf('--ref');
const ref = refArg >= 0 ? process.argv[refArg + 1] : undefined;
const alerts = (await octokit.paginate('GET /repos/{owner}/{repo}/code-scanning/alerts', {
  owner: OWNER, repo: REPO, state: 'open', per_page: 100, ...(ref ? { ref } : {}),
})).filter((a) => a.rule?.id === RULE);

console.log(`Open ${RULE} alerts: ${alerts.length}\n`);
if (alerts.length === 0) process.exit(0);

// Load _vex state
const STATE_REPO = 'git-steer-state';
const { data: file } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner: OWNER, repo: STATE_REPO, path: 'state/cache.json' });
const cacheJson = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));
const existingVex = cacheJson._vex || {};

const now = new Date().toISOString();
const ledgerRows = [];
let written = 0, dismissed = 0;

for (const a of alerts) {
  const loc = `${a.most_recent_instance?.location?.path}:${a.most_recent_instance?.location?.start_line}`;
  const cveId = `codeql/${RULE}#${a.number}`;
  const prevStatus = existingVex[vexId(REPO_FULL, cveId)]?.status ?? null;
  const entry = {
    cve_id: cveId,
    repo: REPO_FULL,
    product_purl: `pkg:github/${REPO_FULL}`,
    status: 'not_affected',
    justification: JUSTIFICATION,
    impact_statement: `${loc} — ${NOTE}`,
    detail: `CodeQL ${RULE} alert #${a.number}. Re-evaluate on next scan (ADR-004 C-004-005).`,
    created_at: now,
    updated_by: 'cli:dismiss-codeql-fp',
  };
  const err = validateVexInput(entry);
  if (err) { console.error(`  [skip] #${a.number}: ${err}`); continue; }

  existingVex[vexId(REPO_FULL, cveId)] = entry;
  ledgerRows.push(makeVexLedgerEntry(entry, prevStatus, 'cli:dismiss-codeql-fp', now));
  written++;

  try {
    await octokit.request('PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}', {
      owner: OWNER, repo: REPO, alert_number: a.number,
      state: 'dismissed', dismissed_reason: 'false positive',
      dismissed_comment: `VEX not_affected (${JUSTIFICATION}): ${NOTE} [ADR-004]`,
    });
    dismissed++;
    console.log(`  ✓ #${a.number}  ${loc}`);
  } catch (e) {
    console.error(`  ! #${a.number} VEX written but dismiss failed: ${e.status} ${e.message}`);
  }
}

cacheJson._vex = existingVex;
await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner: OWNER, repo: STATE_REPO, path: 'state/cache.json',
  content: Buffer.from(JSON.stringify(cacheJson, null, 2)).toString('base64'),
  message: `vex: not_affected for ${written} ${RULE} findings (global rate limiter) +dismiss`,
  sha: file.sha,
});
await appendJsonl(octokit, OWNER, STATE_REPO, 'state/vex.jsonl', ledgerRows);

console.log(`\nVEX written: ${written} | dismissed: ${dismissed} | ledger rows: ${ledgerRows.length}`);
