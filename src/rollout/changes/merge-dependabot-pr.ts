/**
 * merge-dependabot-pr (ADR-011 Fix a repo).
 *
 * One target is one pull request, "owner/repo#N". The owner approved the list
 * on the rollout issue; this re-checks each PR just before merging it:
 *
 *   compliant    - already merged
 *   noncompliant - open, Dependabot's, into the default branch, mergeable,
 *                  and no check failed: merge it
 *   waiting      - in conflict, still computing, or checks still running
 *                  (Dependabot rebases after each merge); retried next step
 *   unavailable  - closed unmerged, not Dependabot's, or a check failed:
 *                  never merged (C-011-003)
 *
 * The merge is a squash pinned to the head SHA that was checked, so a PR that
 * changed after the check is never merged blind. GitHub signs squash merges.
 */

import type { Octokit } from 'octokit';
import type { Change, CheckResult } from '../types.js';

const DEPENDABOT = 'dependabot[bot]';
const FAILED = new Set(['failure', 'timed_out', 'cancelled', 'action_required', 'startup_failure', 'stale']);

export interface PullTarget { owner: string; repo: string; number: number }

export function parsePullTarget(target: string): PullTarget {
  const m = target.match(/^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)#(\d+)$/);
  if (!m) throw new Error(`not a pull request: ${target}`);
  return { owner: m[1], repo: m[2], number: Number(m[3]) };
}

export interface CheckRunLike { name: string; status: string; conclusion: string | null }
export interface StatusLike { context: string; state: string }

export type ChecksVerdict = { state: 'ready' | 'untested' | 'failing' | 'running'; detail: string };

/** What a PR's checks say. Neutral and skipped runs (e.g. CodeQL with nothing to do) don't count as tests. */
export function judgeChecks(runs: CheckRunLike[], statuses: StatusLike[]): ChecksVerdict {
  const failed = [
    ...runs.filter((r) => r.status === 'completed' && FAILED.has(r.conclusion ?? '')).map((r) => r.name),
    ...statuses.filter((s) => s.state === 'failure' || s.state === 'error').map((s) => s.context),
  ];
  if (failed.length) return { state: 'failing', detail: `failed: ${failed.join(', ')}` };
  const running = [
    ...runs.filter((r) => r.status !== 'completed').map((r) => r.name),
    ...statuses.filter((s) => s.state === 'pending').map((s) => s.context),
  ];
  if (running.length) return { state: 'running', detail: `running: ${running.join(', ')}` };
  const passed = [
    ...runs.filter((r) => r.conclusion === 'success').map((r) => r.name),
    ...statuses.filter((s) => s.state === 'success').map((s) => s.context),
  ];
  if (passed.length) return { state: 'ready', detail: `passed: ${[...new Set(passed)].join(', ')}` };
  return { state: 'untested', detail: 'no checks ran' };
}

export interface PullLike {
  state: string;
  merged: boolean;
  mergeable: boolean | null;
  mergeable_state?: string;
  user: { login: string } | null;
  base: { ref: string };
  head: { sha: string };
}

export function judgePull(pr: PullLike, defaultBranch: string, checks: ChecksVerdict): CheckResult {
  if (pr.merged) return { state: 'compliant', detail: 'merged' };
  if (pr.state !== 'open') return { state: 'unavailable', detail: 'closed without merging' };
  if (pr.user?.login !== DEPENDABOT) return { state: 'unavailable', detail: `not a Dependabot PR (${pr.user?.login ?? 'unknown author'})` };
  if (pr.base.ref !== defaultBranch) return { state: 'unavailable', detail: `targets ${pr.base.ref}, not ${defaultBranch}` };
  if (pr.mergeable === null) return { state: 'waiting', detail: 'GitHub is still working out whether it can merge' };
  if (pr.mergeable === false || pr.mergeable_state === 'dirty') return { state: 'waiting', detail: 'in conflict; waiting for Dependabot to rebase' };
  if (checks.state === 'failing') return { state: 'unavailable', detail: checks.detail };
  if (checks.state === 'running') return { state: 'waiting', detail: checks.detail };
  return { state: 'noncompliant', detail: `open, ${checks.state} (${checks.detail}) @ ${pr.head.sha.slice(0, 7)}` };
}

export async function readChecks(octokit: Octokit, owner: string, repo: string, sha: string): Promise<ChecksVerdict> {
  const runs = (await octokit.paginate('GET /repos/{owner}/{repo}/commits/{ref}/check-runs', { owner, repo, ref: sha, per_page: 100 },
    (res) => (res.data as unknown as { check_runs: CheckRunLike[] }).check_runs)) as CheckRunLike[];
  const { data: combined } = await octokit.request('GET /repos/{owner}/{repo}/commits/{ref}/status', { owner, repo, ref: sha });
  return judgeChecks(runs, (combined.statuses ?? []) as StatusLike[]);
}

async function read(octokit: Octokit, target: string): Promise<{ pr: PullLike; verdict: CheckResult }> {
  const { owner, repo, number } = parsePullTarget(target);
  const [{ data: pr }, { data: info }] = await Promise.all([
    octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner, repo, pull_number: number }),
    octokit.request('GET /repos/{owner}/{repo}', { owner, repo }),
  ]);
  const p = pr as unknown as PullLike;
  const checks = p.state === 'open' && !p.merged ? await readChecks(octokit, owner, repo, p.head.sha) : { state: 'untested' as const, detail: '' };
  return { pr: p, verdict: judgePull(p, info.default_branch, checks) };
}

export const mergeDependabotPr: Change = {
  id: 'merge-dependabot-pr',
  target: 'pr',
  summary: 'Merge Dependabot pull requests (squash), one per job, each re-checked just before merging. A PR whose checks failed is never merged.',

  async check(octokit, target) {
    try {
      return (await read(octokit, target)).verdict;
    } catch (err) {
      const e = err as { status?: number; message?: string };
      return { state: 'unknown', detail: `${e.status ?? ''} ${e.message ?? ''}`.trim() };
    }
  },

  async apply(octokit, target) {
    const { owner, repo, number } = parsePullTarget(target);
    const { pr, verdict } = await read(octokit, target);
    if (verdict.state !== 'noncompliant') throw new Error(`no longer mergeable: ${verdict.detail}`);
    await octokit.request('PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', {
      owner, repo, pull_number: number, merge_method: 'squash', sha: pr.head.sha,
    });
  },
};
