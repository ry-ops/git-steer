/**
 * Hand off to Copilot, step 3 (ADR-011): the reply on the request, from
 * handoff-plan.json and every handoff-result-*.json the open jobs left.
 * Writes handoff-reply.md. Reads only local files.
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { renderHandoffReply } from '../dist/fleet/index.js';

const plan = JSON.parse(readFileSync('handoff-plan.json', 'utf8'));
const results = readdirSync('.')
  .filter((f) => /^handoff-result-.+\.json$/.test(f))
  .flatMap((f) => JSON.parse(readFileSync(f, 'utf8')));
writeFileSync('handoff-reply.md', renderHandoffReply(plan, results));
