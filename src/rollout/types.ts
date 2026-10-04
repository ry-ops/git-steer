/**
 * Rollouts (ADR-010): one change, applied to an explicit list of targets a
 * person started and approved, one target per job, checked after every write.
 */

import type { Octokit } from 'octokit';

/**
 * compliant    - nothing to do
 * noncompliant - apply would change it
 * unavailable  - the target's plan doesn't allow it; never written to
 * unknown      - couldn't tell; never written to
 */
export type CheckState = 'compliant' | 'noncompliant' | 'unavailable' | 'unknown';

export interface CheckResult {
  state: CheckState;
  detail: string;
}

export interface Change {
  id: string;
  /** What one target is: "owner/repo" or an org login. */
  target: 'repo' | 'org';
  /** One line, shown on the rollout issue. */
  summary: string;
  check(octokit: Octokit, target: string): Promise<CheckResult>;
  /** Only called after check() said noncompliant (C-010-006). */
  apply(octokit: Octokit, target: string): Promise<void>;
}

export type Outcome = 'already-compliant' | 'applied' | 'unavailable' | 'failed';

export interface TargetResult {
  issue: number;
  change: string;
  target: string;
  outcome: Outcome;
  before: string;
  after: string;
  runUrl?: string;
  at: string;
}
