/**
 * sponsorships (ADR-010).
 *
 * The repo's Sponsorships feature on, so GitHub shows the sponsor button from
 * the owner's .github/FUNDING.yml. It's a per-repo setting, off on every new
 * repo, and only the GraphQL API exposes it. Forks are left alone: a sponsor
 * button on someone else's code would ask for money for their work.
 */

import type { Octokit } from 'octokit';
import type { Change, CheckResult } from '../types.js';

interface RepoFlags {
  id: string;
  isFork: boolean;
  isArchived: boolean;
  hasSponsorshipsEnabled: boolean;
}

function split(target: string): { owner: string; repo: string } {
  const [owner, repo] = target.split('/');
  if (!owner || !repo) throw new Error(`not a repo: ${target}`);
  return { owner, repo };
}

async function readFlags(octokit: Octokit, target: string): Promise<RepoFlags> {
  const { owner, repo } = split(target);
  const { repository } = await octokit.graphql<{ repository: RepoFlags }>(
    'query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){id isFork isArchived hasSponsorshipsEnabled}}',
    { owner, repo },
  );
  return repository;
}

export function evaluateSponsorships(r: Omit<RepoFlags, 'id'>): CheckResult {
  if (r.isArchived) return { state: 'unavailable', detail: 'archived' };
  if (r.isFork) return { state: 'unavailable', detail: 'fork; left off by design' };
  return r.hasSponsorshipsEnabled
    ? { state: 'compliant', detail: 'Sponsorships on' }
    : { state: 'noncompliant', detail: 'Sponsorships off' };
}

export const sponsorships: Change = {
  id: 'sponsorships',
  target: 'repo',
  summary: 'Sponsorships on, so the repo shows the sponsor button from FUNDING.yml (forks left off).',

  async check(octokit, target) {
    try {
      return evaluateSponsorships(await readFlags(octokit, target));
    } catch (err) {
      const e = err as { status?: number; message?: string };
      return { state: 'unknown', detail: `${e.status ?? ''} ${e.message ?? ''}`.trim() };
    }
  },

  async apply(octokit, target) {
    const { id } = await readFlags(octokit, target);
    await octokit.graphql(
      'mutation($id:ID!){updateRepository(input:{repositoryId:$id,hasSponsorshipsEnabled:true}){repository{id}}}',
      { id },
    );
  },
};
