/**
 * Miscellaneous tools: slack_notify, slack_configure, code_quality_sweep, code_review
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';
import { existsSync } from 'fs';
import { execFileSync } from 'child_process';
import { homedir } from 'os';
import { join } from 'path';

export function getTools(): Tool[] {
  return [
    {
      name: 'slack_notify',
      description: 'Send a notification to a Slack channel via webhook. Used for PR events, alerts, and remediation updates.',
      inputSchema: {
        type: 'object',
        properties: {
          channel: { type: 'string', description: 'Channel name or "default" to use configured webhook' },
          message: { type: 'string', description: 'Message text (supports Slack mrkdwn)' },
          blocks: { type: 'array', description: 'Slack Block Kit blocks for rich formatting' },
          webhook_url: { type: 'string', description: 'Slack webhook URL. If omitted, uses configured default from state.' },
        },
        required: ['message'],
      },
    },
    {
      name: 'slack_configure',
      description: 'Configure Slack webhook URL for notifications. Stores in state repo config.',
      inputSchema: {
        type: 'object',
        properties: {
          webhook_url: { type: 'string', description: 'Slack incoming webhook URL' },
          default_channel: { type: 'string', description: 'Default channel name for reference' },
          notify_on: {
            type: 'object',
            description: 'Events to notify on',
            properties: {
              pr_created: { type: 'boolean', default: true },
              pr_merged: { type: 'boolean', default: true },
              pr_dedup_hit: { type: 'boolean', default: false },
              oomkill_detected: { type: 'boolean', default: true },
              cert_expiring: { type: 'boolean', default: true },
            },
          },
        },
        required: ['webhook_url'],
      },
    },
    {
      name: 'code_quality_sweep',
      description: 'Run linters and SAST tools (ESLint, Ruff, gosec, Bandit) on a repository via GitHub Actions. Auto-detects language stack.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          tools: {
            type: 'array',
            items: {
              type: 'string',
              enum: ['eslint', 'ruff', 'gosec', 'bandit', 'auto'],
            },
            default: ['auto'],
            description: 'Linter/SAST tools to run. "auto" detects from language stack.',
          },
          createIssues: {
            type: 'boolean',
            default: false,
            description: 'Create GitHub issues for findings',
          },
          severity: {
            type: 'string',
            enum: ['error', 'warning', 'all'],
            default: 'error',
            description: 'Minimum finding severity to report',
          },
        },
        required: ['owner', 'repo'],
      },
    },
    {
      name: 'code_review',
      description: 'Run AI-powered code review using CodeRabbit CLI. Reviews changes in a local git repository.',
      inputSchema: {
        type: 'object',
        properties: {
          cwd: {
            type: 'string',
            description: 'Working directory path (must be a git repository). Defaults to current directory.',
          },
          type: {
            type: 'string',
            enum: ['all', 'committed', 'uncommitted'],
            description: 'Review type: all changes, only committed, or only uncommitted',
            default: 'all',
          },
          base: {
            type: 'string',
            description: 'Base branch for comparison (e.g., "main", "develop")',
          },
          baseCommit: {
            type: 'string',
            description: 'Base commit SHA on current branch for comparison',
          },
          promptOnly: {
            type: 'boolean',
            description: 'Return minimal output optimized for token efficiency',
            default: false,
          },
          config: {
            type: 'array',
            items: { type: 'string' },
            description: 'Additional config files to include (e.g., ["CLAUDE.md", ".coderabbit.yaml"])',
          },
        },
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'slack_notify': return handleSlackNotify(args, deps);
    case 'slack_configure': return handleSlackConfigure(args, deps);
    case 'code_quality_sweep': return handleCodeQualitySweep(args, deps);
    case 'code_review': return handleCodeReview(args, deps);
    default: return null;
  }
}

async function handleSlackNotify(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const webhookUrl = args.webhook_url || deps.state.getCache('slack_config')?.webhook_url;
  if (!webhookUrl) {
    throw new Error('No Slack webhook URL configured. Use slack_configure first or pass webhook_url.');
  }

  const payload: Record<string, any> = { text: args.message };
  if (args.blocks) payload.blocks = args.blocks;

  await deps.sendSlackNotification(webhookUrl, payload);

  deps.state.addAuditEntry({
    action: 'slack_notify',
    result: 'sent',
    details: { channel: args.channel || 'default' },
  });

  return { success: true, message: 'Notification sent' };
}

async function handleSlackConfigure(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const config = {
    webhook_url: args.webhook_url,
    default_channel: args.default_channel || 'general',
    notify_on: {
      pr_created: true,
      pr_merged: true,
      pr_dedup_hit: false,
      oomkill_detected: true,
      cert_expiring: true,
      ...args.notify_on,
    },
  };

  deps.state.setCache('slack_config', config);

  deps.state.addAuditEntry({
    action: 'slack_configure',
    result: 'configured',
    details: { channel: config.default_channel, events: Object.keys(config.notify_on).filter((k) => (config.notify_on as any)[k]) },
  });

  return { success: true, config };
}

async function handleCodeQualitySweep(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const jobId = `quality-${Date.now()}`;

  if (args.createIssues) {
    await deps.github.ensureLabel(args.owner, args.repo, 'code-quality', '5319e7', 'Code quality findings');
    await deps.github.ensureLabel(args.owner, args.repo, 'automated', 'bfd4f2', 'Created by automation');
  }

  let tools = args.tools || ['auto'];
  if (tools.includes('auto')) {
    const files = await deps.github.listFiles(args.owner, args.repo, '');
    const fileNames = files.map((f) => f.name);
    tools = [];
    if (fileNames.includes('package.json') || fileNames.includes('tsconfig.json')) tools.push('eslint');
    if (fileNames.includes('pyproject.toml') || fileNames.includes('requirements.txt') || fileNames.includes('setup.py')) {
      tools.push('ruff', 'bandit');
    }
    if (fileNames.includes('go.mod')) tools.push('gosec');
    if (tools.length === 0) tools = ['eslint'];
  }

  await deps.github.triggerWorkflow(
    'ry-ops',
    'git-steer',
    'code-quality.yml',
    'main',
    {
      target_owner: args.owner,
      target_repo: args.repo,
      tools: JSON.stringify(tools),
      create_issues: String(args.createIssues || false),
      severity: args.severity || 'error',
      job_id: jobId,
    }
  );

  return {
    success: true,
    jobId,
    repo: `${args.owner}/${args.repo}`,
    tools,
    message: 'Code quality workflow dispatched. Use workflow_status to check progress.',
  };
}

async function handleCodeReview(args: Record<string, any>, _deps: ToolDeps): Promise<any> {
  const coderabbitPaths = [
    join(homedir(), '.local', 'bin', 'coderabbit'),
    '/usr/local/bin/coderabbit',
    '/opt/homebrew/bin/coderabbit',
  ];

  let coderabbitPath: string | null = null;
  for (const p of coderabbitPaths) {
    if (existsSync(p)) {
      coderabbitPath = p;
      break;
    }
  }

  if (!coderabbitPath) {
    throw new Error(
      'CodeRabbit CLI not found. Install it with: curl -fsSL https://cli.coderabbit.ai/install.sh | sh'
    );
  }

  const cmdParts = [coderabbitPath, 'review', '--plain'];

  if (args.promptOnly) {
    cmdParts.push('--prompt-only');
  }

  if (args.type && args.type !== 'all') {
    cmdParts.push('--type', args.type);
  }

  if (args.base) {
    cmdParts.push('--base', args.base);
  }

  if (args.baseCommit) {
    cmdParts.push('--base-commit', args.baseCommit);
  }

  if (args.config && args.config.length > 0) {
    cmdParts.push('--config', ...args.config);
  }

  const cwd = args.cwd || process.cwd();

  const gitDir = join(cwd, '.git');
  if (!existsSync(gitDir)) {
    throw new Error(`Not a git repository: ${cwd}`);
  }

  try {
    const output = execFileSync(cmdParts[0], cmdParts.slice(1), {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
      timeout: 300000,
    });

    return {
      success: true,
      cwd,
      reviewType: args.type || 'all',
      base: args.base || null,
      review: output,
    };
  } catch (error: any) {
    if (error.stdout) {
      return {
        success: true,
        cwd,
        reviewType: args.type || 'all',
        base: args.base || null,
        review: error.stdout,
        stderr: error.stderr || null,
      };
    }
    throw new Error(`CodeRabbit review failed: ${error.message}`);
  }
}
