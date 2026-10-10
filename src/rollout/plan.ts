/**
 * The hourly step's plan (ADR-010): which targets to work on this hour.
 *
 * It only continues rollouts a person started and the owner approved
 * (C-010-002), skips paused ones, and never takes more than the budget
 * across all rollouts (C-010-003). Oldest rollout first.
 *
 * The budget comes from what was actually written, not from when the step
 * runs: writes recorded on rollout issues (open or recently closed) in the
 * last 60 minutes count against the 5, so a late, manual or doubled-up run
 * can't exceed 5 an hour.
 */

import { parseRolloutIssue, remaining } from './issue.js';

export interface RolloutIssue {
  number: number;
  /** Closed issues are passed in only so their recent writes count against the budget. */
  open: boolean;
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
const HOUR_MS = 60 * 60 * 1000;
/** A target found waiting (e.g. a PR Dependabot is rebasing) isn't retried for this long, so it doesn't use up the hour's slots. */
export const WAITING_BACKOFF_MS = 30 * 60 * 1000;

/** Writes recorded in the last hour across every rollout issue given. */
export function recentWrites(issues: RolloutIssue[], now: Date): number {
  let n = 0;
  for (const issue of issues) {
    for (const item of parseRolloutIssue(issue.body)?.items ?? []) {
      // Notes are recorded to the minute; count anything that might be inside the hour.
      if (item.wroteAt && now.getTime() - item.wroteAt.getTime() < HOUR_MS + 60_000) n++;
    }
  }
  return n;
}

export function planStep(
  issues: RolloutIssue[], knownChanges: string[], now = new Date(), hourly = HOURLY_BUDGET,
): { items: StepItem[]; skipped: SkippedRollout[]; recent: number; budget: number } {
  const recent = recentWrites(issues, now);
  const budget = Math.max(0, hourly - recent);
  const items: StepItem[] = [];
  const skipped: SkippedRollout[] = [];
  for (const issue of [...issues].filter((i) => i.open).sort((a, b) => a.number - b.number)) {
    const rollout = parseRolloutIssue(issue.body);
    if (!rollout) { skipped.push({ issue: issue.number, reason: 'not a rollout issue' }); continue; }
    if (!issue.openedByGitSteer) { skipped.push({ issue: issue.number, reason: 'not opened by the start workflow' }); continue; }
    if (!knownChanges.includes(rollout.change)) { skipped.push({ issue: issue.number, reason: `unknown change ${rollout.change}` }); continue; }
    if (issue.labels.includes('paused')) { skipped.push({ issue: issue.number, reason: 'paused' }); continue; }
    if (!issue.approvedByOwner) { skipped.push({ issue: issue.number, reason: 'waiting for approval' }); continue; }
    for (const item of remaining(rollout)) {
      if (item.waitingAt && now.getTime() - item.waitingAt.getTime() < WAITING_BACKOFF_MS) continue;
      if (items.length >= budget) return { items, skipped, recent, budget };
      items.push({ issue: issue.number, change: rollout.change, target: item.target });
    }
  }
  return { items, skipped, recent, budget };
}
