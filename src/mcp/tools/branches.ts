/**
 * Branch tools: branch_list, branch_protect, branch_reap
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';

export function getTools(): Tool[] {
  return [
    {
      name: 'branch_list',
      description: 'List branches with staleness information',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          staleDays: {
            type: 'number',
            description: 'Mark branches older than this as stale',
            default: 30,
          },
        },
        required: ['owner', 'repo'],
      },
    },
    {
      name: 'branch_protect',
      description: 'Apply branch protection rules',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          branch: { type: 'string' },
          policy: {
            type: 'string',
            description: 'Named policy from config, or "custom"',
          },
          customRules: {
            type: 'object',
            description: 'Custom rules if policy is "custom"',
            properties: {
              requiredReviews: { type: 'number' },
              dismissStaleReviews: { type: 'boolean' },
              requireCodeOwnerReviews: { type: 'boolean' },
              requireStatusChecks: {
                type: 'array',
                items: { type: 'string' },
              },
            },
          },
        },
        required: ['owner', 'repo', 'branch'],
      },
    },
    {
      name: 'branch_reap',
      description: 'Delete stale or merged branches',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          daysStale: { type: 'number', default: 30 },
          exclude: {
            type: 'array',
            items: { type: 'string' },
            description: 'Branches to never delete',
            default: ['main', 'master', 'develop'],
          },
          dryRun: {
            type: 'boolean',
            description: 'List branches without deleting',
            default: false,
          },
          confirm: { type: 'string', description: "Safety confirmation. Must be exactly 'CONFIRM_BRANCH_REAP' to proceed." },
        },
        required: ['owner', 'repo'],
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'branch_list': return handleBranchList(args, deps);
    case 'branch_protect': return handleBranchProtect(args, deps);
    case 'branch_reap': return handleBranchReap(args, deps);
    default: return null;
  }
}

async function handleBranchList(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const branches = await deps.github.listBranchesGraphQL(args.owner, args.repo);
  const staleDays = args.staleDays || 30;
  const staleDate = new Date();
  staleDate.setDate(staleDate.getDate() - staleDays);

  return branches.map((b) => ({
    ...b,
    stale: b.lastCommitDate < staleDate,
    daysOld: Math.floor(
      (Date.now() - b.lastCommitDate.getTime()) / (1000 * 60 * 60 * 24)
    ),
  }));
}

async function handleBranchProtect(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  let rules = args.customRules || {};

  if (args.policy && args.policy !== 'custom') {
    const policies = deps.state.getPolicies();
    const policy = policies[args.policy];
    if (policy?.protection) {
      rules = {
        requiredReviews: policy.protection.required_reviews,
        dismissStaleReviews: policy.protection.dismiss_stale_reviews,
        requireCodeOwnerReviews: policy.protection.require_code_owner_reviews,
      };
    }
  }

  await deps.github.protectBranch(args.owner, args.repo, args.branch, rules);
  return { protected: true, branch: args.branch, rules };
}

async function handleBranchReap(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const branches = await deps.github.listBranchesGraphQL(args.owner, args.repo);
  const staleDays = args.daysStale || 30;
  const staleDate = new Date();
  staleDate.setDate(staleDate.getDate() - staleDays);
  const exclude = args.exclude || ['main', 'master', 'develop'];

  const toDelete = branches.filter(
    (b) =>
      !b.protected &&
      !exclude.includes(b.name) &&
      b.lastCommitDate < staleDate
  );

  if (args.dryRun) {
    return {
      dryRun: true,
      wouldDelete: toDelete.map((b) => b.name),
    };
  }

  const deleted: string[] = [];
  for (const branch of toDelete) {
    await deps.github.deleteBranch(args.owner, args.repo, branch.name);
    deleted.push(branch.name);
  }

  return { deleted };
}
