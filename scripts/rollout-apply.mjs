/**
 * One target, one job (ADR-010): check, apply only if needed, check again.
 * Writes result.json. Always exits 0 when it got as far as a result; the
 * outcome (including "failed") is in the result.
 *
 * Env vars:
 *   GH_TOKEN        - git-steer-admin token minted for this one target (C-010-001)
 *   CHANGE, TARGET, ISSUE, RUN_URL
 */

import { Octokit } from 'octokit';
import { writeFileSync } from 'node:fs';
import { CHANGES, applyToTarget } from '../dist/rollout/index.js';

const { GH_TOKEN, CHANGE = '', TARGET = '', ISSUE = '0', RUN_URL } = process.env;
const change = CHANGES[CHANGE];
if (!change || !TARGET || !GH_TOKEN) {
  console.error('CHANGE (known), TARGET and GH_TOKEN are required.');
  process.exit(1);
}

const result = await applyToTarget(change, new Octokit({ auth: GH_TOKEN }), Number(ISSUE), TARGET, RUN_URL);
writeFileSync('result.json', JSON.stringify(result, null, 2));
console.log(`${result.target}: ${result.outcome} (${result.before} → ${result.after})`);
