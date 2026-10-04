/**
 * The hourly step's plan (ADR-010): which targets to work on this hour.
 *
 * It only continues rollouts a person started and the owner approved
 * (C-010-002), skips paused ones, and never takes more than the budget
 * across all rollouts (C-010-003). Oldest rollout first.
 */

import { parseRolloutIssue, remaining } from './issue.js';

export interface RolloutIssue {
  number: number;
  body: string;
  labels: string[];
  /** The issue was opened by the start workflow (github-actions[bot]). */
  openedByGitSteer: boolean;
  /** The `approved` label is on, and the repo owner is who added it. */
  approvedByOwner: boolean;
}

export interface StepItem {
  issue: number;
  change: string;
  target: string;
}

export interface SkippedRollout {
  issue: number;
  reason: string;
}

export const HOURLY_BUDGET = 5;

export function planStep(issues: RolloutIssue[], knownChanges: string[], budget = HOURLY_BUDGET): { items: StepItem[]; skipped: SkippedRollout[] } {
  const items: StepItem[] = [];
  const skipped: SkippedRollout[] = [];
  for (const issue of [...issues].sort((a, b) => a.number - b.number)) {
    const rollout = parseRolloutIssue(issue.body);
    if (!rollout) { skipped.push({ issue: issue.number, reason: 'not a rollout issue' }); continue; }
    if (!issue.openedByGitSteer) { skipped.push({ issue: issue.number, reason: 'not opened by the start workflow' }); continue; }
    if (!knownChanges.includes(rollout.change)) { skipped.push({ issue: issue.number, reason: `unknown change ${rollout.change}` }); continue; }
    if (issue.labels.includes('paused')) { skipped.push({ issue: issue.number, reason: 'paused' }); continue; }
    if (!issue.approvedByOwner) { skipped.push({ issue: issue.number, reason: 'waiting for approval' }); continue; }
    for (const item of remaining(rollout)) {
      if (items.length >= budget) return { items, skipped };
      items.push({ issue: issue.number, change: rollout.change, target: item.target });
    }
  }
  return { items, skipped };
}
