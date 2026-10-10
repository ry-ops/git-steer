import { defaultBranchRuleset } from './changes/default-branch-ruleset.js';
import { mergeDependabotPr } from './changes/merge-dependabot-pr.js';
import { securitySettings } from './changes/security-settings.js';
import type { Change } from './types.js';

/** Change types git-steer can roll out. New ones are added here, by PR. */
export const CHANGES: Record<string, Change> = {
  [defaultBranchRuleset.id]: defaultBranchRuleset,
  [securitySettings.id]: securitySettings,
  [mergeDependabotPr.id]: mergeDependabotPr,
};

export { applyToTarget } from './apply.js';
export { planStep, recentWrites, HOURLY_BUDGET } from './plan.js';
export { parseRolloutIssue, recordResult, remaining, renderRolloutIssue } from './issue.js';
export type { Change, CheckResult, TargetResult } from './types.js';
export type { RolloutIssue, StepItem } from './plan.js';
