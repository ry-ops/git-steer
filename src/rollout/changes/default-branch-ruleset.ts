/**
 * default-branch-ruleset (ADR-010, ADR-008 Layer 0).
 *
 * One repository ruleset, owned by git-steer, on the default branch:
 * pull request required, signed commits, linear history, no force-push, no
 * deletion. Repo admins (the owner) can always bypass. Required status checks
 * are per repo and come later through .github/git-steer.yml.
 */

import type { Octokit } from 'octokit';
import { isPlanLimited } from '../../fleet/classify.js';
import type { Change, CheckResult } from '../types.js';

export const RULESET_NAME = 'git-steer: default branch';

/** GitHub's built-in repository role id for "admin". */
const ADMIN_ROLE_ID = 5;

export const REQUIRED_RULES = ['deletion', 'non_fast_forward', 'pull_request', 'required_linear_history', 'required_signatures'] as const;

export interface RulesetLike {
  id?: number;
  name?: string;
  target?: string;
  enforcement?: string;
  conditions?: { ref_name?: { include?: string[]; exclude?: string[] } } | null;
  bypass_actors?: { actor_id?: number | null; actor_type?: string; bypass_mode?: string }[] | null;
  rules?: { type: string }[];
}

export function desiredRuleset() {
  return {
    name: RULESET_NAME,
    target: 'branch' as const,
    enforcement: 'active' as const,
    conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
    bypass_actors: [{ actor_id: ADMIN_ROLE_ID, actor_type: 'RepositoryRole' as const, bypass_mode: 'always' as const }],
    rules: [
      { type: 'deletion' as const },
      { type: 'non_fast_forward' as const },
      { type: 'required_linear_history' as const },
      { type: 'required_signatures' as const },
      {
        type: 'pull_request' as const,
        parameters: {
          required_approving_review_count: 0,
          dismiss_stale_reviews_on_push: false,
          require_code_owner_review: false,
          require_last_push_approval: false,
          required_review_thread_resolution: false,
        },
      },
    ],
  };
}

/** Compares git-steer's ruleset as GitHub returns it with what it should be. */
export function evaluateRuleset(existing: RulesetLike | null): CheckResult {
  if (!existing) return { state: 'noncompliant', detail: 'no git-steer ruleset' };
  const problems: string[] = [];
  if (existing.enforcement !== 'active') problems.push(`enforcement ${existing.enforcement}`);
  if (!existing.conditions?.ref_name?.include?.includes('~DEFAULT_BRANCH')) problems.push('not on the default branch');
  const have = new Set((existing.rules ?? []).map((r) => r.type));
  const missing = REQUIRED_RULES.filter((t) => !have.has(t));
  if (missing.length) problems.push(`missing rules: ${missing.join(', ')}`);
  const adminBypass = (existing.bypass_actors ?? []).some(
    (a) => a.actor_type === 'RepositoryRole' && a.actor_id === ADMIN_ROLE_ID && a.bypass_mode === 'always');
  if (!adminBypass) problems.push('no admin bypass');
  return problems.length
    ? { state: 'noncompliant', detail: problems.join('; ') }
    : { state: 'compliant', detail: `ruleset #${existing.id} active` };
}

function split(target: string): { owner: string; repo: string } {
  const [owner, repo] = target.split('/');
  if (!owner || !repo) throw new Error(`not a repo: ${target}`);
  return { owner, repo };
}

async function findOurs(octokit: Octokit, target: string): Promise<{ ruleset: RulesetLike | null } | CheckResult> {
  const { owner, repo } = split(target);
  try {
    const { data: list } = await octokit.request('GET /repos/{owner}/{repo}/rulesets', { owner, repo, per_page: 100, includes_parents: false });
    const summary = (list as RulesetLike[]).find((r) => r.name === RULESET_NAME);
    if (!summary?.id) return { ruleset: null };
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', { owner, repo, ruleset_id: summary.id });
    return { ruleset: data as RulesetLike };
  } catch (err) {
    const e = err as { status?: number; response?: { data?: { message?: string } }; message?: string };
    const message = e.response?.data?.message ?? e.message ?? '';
    if (e.status === 403 && isPlanLimited(message)) return { state: 'unavailable', detail: message };
    return { state: 'unknown', detail: `${e.status ?? ''} ${message}`.trim() };
  }
}

export const defaultBranchRuleset: Change = {
  id: 'default-branch-ruleset',
  target: 'repo',
  summary: 'Default-branch ruleset: pull request required, signed commits, linear history, no force-push or deletion; repo admins can bypass.',

  async check(octokit, target) {
    const found = await findOurs(octokit, target);
    return 'state' in found ? found : evaluateRuleset(found.ruleset);
  },

  async apply(octokit, target) {
    const { owner, repo } = split(target);
    const found = await findOurs(octokit, target);
    if ('state' in found) throw new Error(`cannot read rulesets: ${found.detail}`);
    const body = desiredRuleset();
    if (found.ruleset?.id) {
      await octokit.request('PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}', { owner, repo, ruleset_id: found.ruleset.id, ...body });
    } else {
      await octokit.request('POST /repos/{owner}/{repo}/rulesets', { owner, repo, ...body });
    }
  },
};
