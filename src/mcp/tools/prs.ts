/**
 * PR deduplication tools: pr_dedup_check, pr_dedup_create
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';

export function getTools(): Tool[] {
  return [
    {
      name: 'pr_dedup_check',
      description: 'Check if an open PR with a matching title prefix already exists. Returns the existing PR if found, or null. Use before creating alert/remediation PRs to avoid duplicates.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner' },
          repo: { type: 'string', description: 'Repository name' },
          title_prefix: { type: 'string', description: 'Title prefix to match against open PRs (e.g., "[GitOps Alert]")' },
        },
        required: ['owner', 'repo', 'title_prefix'],
      },
    },
    {
      name: 'pr_dedup_create',
      description: 'Create a PR only if no open PR with the same title prefix exists. If a duplicate is found, returns the existing PR instead. Prevents alert PR spam from automated observers.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner' },
          repo: { type: 'string', description: 'Repository name' },
          title: { type: 'string', description: 'PR title' },
          title_prefix: { type: 'string', description: 'Title prefix for dedup matching. If omitted, uses text before the first " — " in the title.' },
          head: { type: 'string', description: 'Head branch' },
          base: { type: 'string', description: 'Base branch (default: main)' },
          body: { type: 'string', description: 'PR body' },
          labels: { type: 'array', items: { type: 'string' }, description: 'Labels to apply' },
        },
        required: ['owner', 'repo', 'title', 'head'],
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'pr_dedup_check': return handlePrDedupCheck(args, deps);
    case 'pr_dedup_create': return handlePrDedupCreate(args, deps);
    default: return null;
  }
}

async function handlePrDedupCheck(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const openPrs = await deps.github.listPullRequests(args.owner, args.repo, { state: 'open' });
  const match = openPrs.find((pr) => pr.title.startsWith(args.title_prefix));

  deps.state.addAuditEntry({
    action: 'pr_dedup_check',
    repo: `${args.owner}/${args.repo}`,
    result: match ? 'duplicate_found' : 'no_duplicate',
    details: { title_prefix: args.title_prefix, matchedPr: match?.number },
  });

  return match
    ? { duplicate: true, existing_pr: match }
    : { duplicate: false, existing_pr: null };
}

async function handlePrDedupCreate(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const prefix = args.title_prefix || args.title.split(' — ')[0];
  const openPrs = await deps.github.listPullRequests(args.owner, args.repo, { state: 'open' });
  const existing = openPrs.find((pr) => pr.title.startsWith(prefix));

  if (existing) {
    deps.state.addAuditEntry({
      action: 'pr_dedup_create',
      repo: `${args.owner}/${args.repo}`,
      result: 'dedup_hit',
      details: { title_prefix: prefix, existingPr: existing.number },
    });

    const slackConfig = deps.state.getCache('slack_config');
    if (slackConfig?.webhook_url && slackConfig?.notify_on?.pr_dedup_hit) {
      await deps.sendSlackNotification(slackConfig.webhook_url, {
        text: `🔁 PR dedup: skipped duplicate for \`${args.owner}/${args.repo}\`\nExisting: <${existing.htmlUrl}|#${existing.number} ${existing.title}>`,
      });
    }

    return {
      created: false,
      dedup_hit: true,
      existing_pr: existing,
      message: `Duplicate PR found: #${existing.number}`,
    };
  }

  const pr = await deps.github.createPullRequest(args.owner, args.repo, {
    title: args.title,
    body: args.body || '',
    head: args.head,
    base: args.base || 'main',
    labels: args.labels,
  });

  deps.state.addAuditEntry({
    action: 'pr_dedup_create',
    repo: `${args.owner}/${args.repo}`,
    result: 'created',
    details: { prNumber: pr.number, title: args.title },
  });

  const slackConfig = deps.state.getCache('slack_config');
  if (slackConfig?.webhook_url && slackConfig?.notify_on?.pr_created) {
    await deps.sendSlackNotification(slackConfig.webhook_url, {
      text: `📋 New PR opened in \`${args.owner}/${args.repo}\`\n<${pr.url}|#${pr.number} ${args.title}>`,
    });
  }

  return {
    created: true,
    dedup_hit: false,
    pr: { number: pr.number, url: pr.url },
  };
}
