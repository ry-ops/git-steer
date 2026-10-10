/**
 * Start a rollout (ADR-010). Writes rollout-title.txt and rollout-body.md;
 * the workflow opens the issue. A selector reads fleet-status/status.json,
 * the latest fleet report, which the workflow downloads. Nothing is changed until the repo owner adds
 * the `approved` label.
 *
 * Env vars:
 *   CHANGE       - a change type id (src/rollout/index.ts)
 *   TARGETS      - targets separated by commas, spaces or newlines ("owner/repo",
 *                  or an org for org changes), or a selector over the latest
 *                  fleet report: "coverage:<check>=<state>", e.g.
 *                  "coverage:branchProtection=off"
 *   STARTED_BY, RUN_URL - who started it, and the run (set by the workflow)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { CHANGES, renderRolloutIssue } from '../dist/rollout/index.js';

const { CHANGE = '', TARGETS = '', STARTED_BY = 'unknown', RUN_URL } = process.env;

const change = CHANGES[CHANGE];
if (!change) {
  console.error(`Unknown change "${CHANGE}". Known: ${Object.keys(CHANGES).join(', ')}`);
  process.exit(1);
}

let targets;
let selector;
const sel = TARGETS.trim().match(/^coverage:([A-Za-z]+)=([a-z]+)$/);
if (sel) {
  const status = JSON.parse(readFileSync('fleet-status/status.json', 'utf8'));
  targets = status.repos.filter((r) => r.coverage?.[sel[1]] === sel[2]).map((r) => r.repo);
  selector = TARGETS.trim();
} else {
  targets = TARGETS.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
}

const shape = change.target === 'repo' ? /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/
  : change.target === 'pr' ? /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+#\d+$/ : /^[A-Za-z0-9._-]+$/;
const bad = targets.filter((t) => !shape.test(t));
if (bad.length) { console.error(`Not a ${change.target}: ${bad.join(', ')}`); process.exit(1); }
targets = [...new Set(targets)];
if (!targets.length) { console.error('No targets.'); process.exit(1); }

const { title, body } = renderRolloutIssue({ change: change.id, summary: change.summary, targets, startedBy: STARTED_BY, runUrl: RUN_URL, selector });
writeFileSync('rollout-title.txt', title);
writeFileSync('rollout-body.md', body);
console.log(`${title}\n${targets.join('\n')}`);
