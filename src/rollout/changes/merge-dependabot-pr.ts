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

/**
 * Scanners and linters look at code; they don't build or test it. A failing
 * one still blocks a merge, but a passing one isn't evidence the upgrade
 * works (on 2026-10-10 git-fabric/chat's only passing check was Codacy, and
 * ry-ops/commit-relay's a workflow named "security").
 */
export const SCANNER = /codeql|codacy|sonar|snyk|semgrep|gitguardian|gitleaks|trivy|socket|mend|whitesource|dependency[- ]review|security|secret|\baudit\b|\bscan|analy[sz]e|lint/i;

/**
 * What a PR's checks say. Neutral and skipped runs don't count, and neither do
 * passing scanners: "ready" needs a passing check that builds or tests.
 */
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
  const passed = [...new Set([
    ...runs.filter((r) => r.conclusion === 'success').map((r) => r.name),
    ...statuses.filter((s) => s.state === 'success').map((s) => s.context),
  ])];
  const tests = passed.filter((n) => !SCANNER.test(n));
  if (tests.length) return { state: 'ready', detail: `passed: ${tests.join(', ')}` };
  if (passed.length) return { state: 'untested', detail: `only scanners passed (${passed.join(', ')}); nothing built or tested it` };
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

/** @param requireChecks merge only when a check passed; a PR with no checks is skipped (merge-dependabot-pr-tested). */
export function judgePull(pr: PullLike, defaultBranch: string, checks: ChecksVerdict, requireChecks = false): CheckResult {
  if (pr.merged) return { state: 'compliant', detail: 'merged' };
  if (pr.state !== 'open') return { state: 'unavailable', detail: 'closed without merging' };
  if (pr.user?.login !== DEPENDABOT) return { state: 'unavailable', detail: `not a Dependabot PR (${pr.user?.login ?? 'unknown author'})` };
  if (pr.base.ref !== defaultBranch) return { state: 'unavailable', detail: `targets ${pr.base.ref}, not ${defaultBranch}` };
  if (pr.mergeable === null) return { state: 'waiting', detail: 'GitHub is still working out whether it can merge' };
  if (pr.mergeable === false || pr.mergeable_state === 'dirty') return { state: 'waiting', detail: 'in conflict; waiting for Dependabot to rebase' };
  if (checks.state === 'failing') return { state: 'unavailable', detail: checks.detail };
  if (checks.state === 'running') return { state: 'waiting', detail: checks.detail };
  if (requireChecks && checks.state === 'untested') return { state: 'unavailable', detail: 'no checks ran, and this rollout merges only PRs whose checks passed' };
  return { state: 'noncompliant', detail: `open, ${checks.state} (${checks.detail}) @ ${pr.head.sha.slice(0, 7)}` };
}

/**
 * @param tolerateStatuses for the read-only plan: if commit statuses can't be
 *   read (the reporter App lacks statuses: read on private repos), judge on
 *   check runs alone and say so. The merge step never tolerates it: its
 *   token can read statuses, and an error there stops the merge.
 */
export async function readChecks(octokit: Octokit, owner: string, repo: string, sha: string, tolerateStatuses = false): Promise<ChecksVerdict> {
  // paginate already unwraps check_runs from this endpoint's { total_count, check_runs } pages.
  const runs = (await octokit.paginate('GET /repos/{owner}/{repo}/commits/{ref}/check-runs', { owner, repo, ref: sha, per_page: 100 })) as unknown as CheckRunLike[];
  let statuses: StatusLike[] = [];
  let note = '';
  try {
    const { data: combined } = await octokit.request('GET /repos/{owner}/{repo}/commits/{ref}/status', { owner, repo, ref: sha });
    statuses = (combined.statuses ?? []) as StatusLike[];
  } catch (err) {
    if (!tolerateStatuses) throw err;
    note = ' (commit statuses not readable; check runs only)';
  }
  const v = judgeChecks(runs, statuses);
  return note ? { ...v, detail: v.detail + note } : v;
}

/**
 * GitHub works out mergeability in the background and answers null until it
 * has (e.g. right after another PR merged into the base). Asking again a few
 * seconds later usually gets the answer, instead of losing a whole step.
 */
export async function getPull(
  octokit: Octokit, owner: string, repo: string, number: number, tries = 4, waitMs = 3000,
): Promise<PullLike & { body?: string | null; title?: string; html_url?: string; number?: number }> {
  for (let i = 1; ; i++) {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner, repo, pull_number: number });
    const pr = data as unknown as PullLike;
    if (pr.mergeable !== null || pr.state !== 'open' || i >= tries) return data as unknown as PullLike;
    await new Promise((r) => setTimeout(r, waitMs));
  }
}

async function read(octokit: Octokit, target: string, requireChecks = false): Promise<{ pr: PullLike; verdict: CheckResult }> {
  const { owner, repo, number } = parsePullTarget(target);
  const [p, { data: info }] = await Promise.all([
    getPull(octokit, owner, repo, number),
    octokit.request('GET /repos/{owner}/{repo}', { owner, repo }),
  ]);
  const checks = p.state === 'open' && !p.merged ? await readChecks(octokit, owner, repo, p.head.sha) : { state: 'untested' as const, detail: '' };
  return { pr: p, verdict: judgePull(p, info.default_branch, checks, requireChecks) };
}

function mergeChange(id: string, requireChecks: boolean, summary: string): Change {
  return {
    id,
    target: 'pr',
    summary,

    async check(octokit, target) {
      try {
        return (await read(octokit, target, requireChecks)).verdict;
      } catch (err) {
        const e = err as { status?: number; message?: string };
        return { state: 'unknown', detail: `${e.status ?? ''} ${e.message ?? ''}`.trim() };
      }
    },

    async apply(octokit, target) {
      const { owner, repo, number } = parsePullTarget(target);
      const { pr, verdict } = await read(octokit, target, requireChecks);
      if (verdict.state !== 'noncompliant') throw new Error(`no longer mergeable: ${verdict.detail}`);
      await octokit.request('PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', {
        owner, repo, pull_number: number, merge_method: 'squash', sha: pr.head.sha,
      });
    },

    // An App without the workflows permission can merge a PR that changes
    // .github/workflows only while the PR is level with its base: once a
    // sibling Dependabot PR has merged, the squash would write workflow
    // content the PR doesn't have, and GitHub refuses (2026-10-10,
    // ry-ops/proxmox-mcp-server#55 after #53).
    refused(err) {
      if (err.status === 403 && /without `?workflows`? permission/.test(err.message ?? '')) {
        return 'changes workflow files and is behind its base, which git-steer-admin can\'t merge without the workflows permission. Comment `@dependabot rebase` on it; a later Fix can then merge it.';
      }
      return null;
    },
  };
}

export const mergeDependabotPr = mergeChange('merge-dependabot-pr', false,
  'Merge Dependabot pull requests (squash), one per job, each re-checked just before merging. A PR whose checks failed is never merged.');

/** Fleet default (ADR-011): only PRs whose checks passed; untested ones are skipped at merge time too. */
export const mergeDependabotPrTested = mergeChange('merge-dependabot-pr-tested', true,
  'Merge Dependabot pull requests whose checks passed (squash), one per job, each re-checked just before merging. PRs with no checks, or a failed check, are skipped.');
