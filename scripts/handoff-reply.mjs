/**
 * Hand off to Copilot, step 3 (ADR-011): the reply on the request, from
 * handoff-plan.json and the handoff-result.json each open job left in its own folder.
 * Writes handoff-reply.md. Reads only local files.
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { renderHandoffReply } from '../dist/fleet/index.js';

const plan = JSON.parse(readFileSync('handoff-plan.json', 'utf8'));
// Each open job's result is downloaded into its own folder, handoff-result-<owner>-<name>/.
const results = readdirSync('.', { withFileTypes: true })
  .filter((d) => d.isDirectory() && d.name.startsWith('handoff-result-'))
  .flatMap((d) => { try { return JSON.parse(readFileSync(`${d.name}/handoff-result.json`, 'utf8')); } catch { return []; } });
writeFileSync('handoff-reply.md', renderHandoffReply(plan, results));
