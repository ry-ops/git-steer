/**
 * Rollouts (ADR-010): one change, applied to an explicit list of targets a
 * person started and approved, one target per job, checked after every write.
 */

import type { Octokit } from 'octokit';

/**
 * compliant    - nothing to do
 * noncompliant - apply would change it
 * unavailable  - the target's plan doesn't allow it, or it can no longer be
 *                done (e.g. a pull request closed); never written to
 * unknown      - couldn't tell; never written to
 * waiting      - not ready yet (e.g. a pull request being rebased); not
 *                written to, not a failure, retried next step
 */
export type CheckState = 'compliant' | 'noncompliant' | 'unavailable' | 'unknown' | 'waiting';

export interface CheckResult {
  state: CheckState;
  detail: string;
}

export interface Change {
  id: string;
  /** What one target is: "owner/repo", an org login, or a pull request "owner/repo#N". */
  target: 'repo' | 'org' | 'pr';
  /** One line, shown on the rollout issue. */
  summary: string;
  check(octokit: Octokit, target: string): Promise<CheckResult>;
  /** Only called after check() said noncompliant (C-010-006). */
  apply(octokit: Octokit, target: string): Promise<void>;
  /**
   * An apply error GitHub raises for a known reason that's no fault of the
   * target, as a detail; the target is then skipped instead of pausing the
   * rollout. Null for any other error.
   */
  refused?(err: { status?: number; message?: string }): string | null;
}

export type Outcome = 'already-compliant' | 'applied' | 'unavailable' | 'failed' | 'waiting';

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
