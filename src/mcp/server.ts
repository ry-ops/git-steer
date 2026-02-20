/**
 * MCP Server for git-steer
 * 
 * Exposes all git-steer capabilities as MCP tools.
 * Supports stdio and HTTP/SSE transports.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { GitHubClient, RateLimitSnapshot } from '../github/client.js';
import { StateManager } from '../state/manager.js';
import { readLimit, writeLimit } from '../core/concurrency.js';
import { generateReport } from '../reports/templates.js';
import { generateDashboardHtml } from '../dashboard/templates.js';
import { createRequire } from 'module';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { randomUUID } from 'crypto';
import type { IncomingMessage, ServerResponse } from 'http';

const require = createRequire(import.meta.url);
const { version: VERSION } = require('../../package.json');

export interface MCPServerConfig {
  github: GitHubClient;
  state: StateManager;
  transport: 'stdio' | 'http';
  port?: number;
}

const TOOLS: Tool[] = [
  // ========== Repository Tools ==========
  {
    name: 'repo_list',
    description: 'List all repositories git-steer has access to',
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type: 'string',
          description: 'Filter by name pattern (glob)',
        },
        includeArchived: {
          type: 'boolean',
          description: 'Include archived repos',
          default: false,
        },
      },
    },
  },
  {
    name: 'repo_create',
    description: 'Create a new repository',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Make repo private', default: true },
        template: {
          type: 'object',
          description: 'Create from template',
          properties: {
            owner: { type: 'string' },
            repo: { type: 'string' },
          },
        },
        addToManaged: {
          type: 'boolean',
          description: 'Add to managed repos with default policies',
          default: true,
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'repo_archive',
    description: 'Archive a repository',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'repo_delete',
    description: 'Permanently delete a repository. Requires confirmation.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        confirm: {
          type: 'string',
          description: 'Type the full repo name to confirm deletion',
        },
      },
      required: ['owner', 'repo', 'confirm'],
    },
  },
  {
    name: 'repo_settings',
    description: 'Update repository settings',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        settings: {
          type: 'object',
          properties: {
            description: { type: 'string' },
            homepage: { type: 'string' },
            private: { type: 'boolean' },
            hasIssues: { type: 'boolean' },
            hasProjects: { type: 'boolean' },
            hasWiki: { type: 'boolean' },
            defaultBranch: { type: 'string' },
          },
        },
      },
      required: ['owner', 'repo', 'settings'],
    },
  },

  // ========== Branch Tools ==========
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
      },
      required: ['owner', 'repo'],
    },
  },

  // ========== Security Tools ==========
  {
    name: 'security_alerts',
    description: 'List security alerts (Dependabot, code scanning)',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'all'],
          default: 'all',
        },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'security_dismiss',
    description: 'Dismiss a security alert with reason',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        alertId: { type: 'number' },
        reason: {
          type: 'string',
          enum: ['fix_started', 'inaccurate', 'no_bandwidth', 'not_used', 'tolerable_risk'],
        },
      },
      required: ['owner', 'repo', 'alertId', 'reason'],
    },
  },
  {
    name: 'security_digest',
    description: 'Generate security summary across all managed repos',
    inputSchema: {
      type: 'object',
      properties: {
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'all'],
          default: 'high',
        },
      },
    },
  },

  // ========== Actions Tools ==========
  {
    name: 'actions_workflows',
    description: 'List workflows in a repository',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'actions_trigger',
    description: 'Manually trigger a workflow',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        workflow: { type: 'string', description: 'Workflow filename or ID' },
        ref: { type: 'string', description: 'Branch or tag', default: 'main' },
        inputs: {
          type: 'object',
          description: 'Workflow inputs',
        },
      },
      required: ['owner', 'repo', 'workflow'],
    },
  },
  {
    name: 'actions_secrets',
    description: 'Manage Actions secrets',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        action: {
          type: 'string',
          enum: ['list', 'set', 'delete'],
        },
        name: { type: 'string' },
        value: { type: 'string', description: 'Secret value (for set)' },
      },
      required: ['owner', 'repo', 'action'],
    },
  },

  // ========== State/Config Tools ==========
  {
    name: 'steer_status',
    description: 'Show git-steer status, rate limits, and health',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'steer_sync',
    description: 'Force sync state to GitHub',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'steer_logs',
    description: 'Show recent audit log entries',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', default: 20 },
        action: { type: 'string', description: 'Filter by action type' },
      },
    },
  },
  {
    name: 'config_show',
    description: 'Display current configuration',
    inputSchema: {
      type: 'object',
      properties: {
        section: {
          type: 'string',
          enum: ['repos', 'policies', 'schedules', 'all'],
          default: 'all',
        },
      },
    },
  },
  {
    name: 'config_add_repo',
    description: 'Add a repository to managed repos',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        name: { type: 'string', description: 'Repo name or "*" for all' },
        policies: {
          type: 'array',
          items: { type: 'string' },
          description: 'Policies to apply',
        },
      },
      required: ['owner', 'name'],
    },
  },
  {
    name: 'config_remove_repo',
    description: 'Remove a repository from managed repos',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        name: { type: 'string' },
      },
      required: ['owner', 'name'],
    },
  },

  // ========== Security Workflow Tools ==========
  {
    name: 'security_scan',
    description: 'Scan repositories for security vulnerabilities with detailed fix information',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string', description: 'Repo name or "*" to scan all accessible repos' },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'all'],
          default: 'all',
        },
      },
      required: ['owner'],
    },
  },
  {
    name: 'security_fix_pr',
    description: 'Dispatch a GitHub Actions workflow to fix security vulnerabilities (no local code needed - runs in ephemeral cloud compute)',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'all'],
          default: 'critical',
          description: 'Minimum severity to fix',
        },
        dryRun: {
          type: 'boolean',
          default: false,
          description: 'Preview changes without creating PR',
        },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'workflow_status',
    description: 'Check status of dispatched workflows',
    inputSchema: {
      type: 'object',
      properties: {
        workflow: {
          type: 'string',
          enum: ['security-fix', 'heartbeat'],
          default: 'security-fix',
        },
        limit: {
          type: 'number',
          default: 5,
        },
      },
    },
  },

  // ========== File Operations ==========
  {
    name: 'repo_commit',
    description: 'Commit files directly to a repository via GitHub API (no local clone needed). Supports multiple files in a single commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        branch: { type: 'string', description: 'Branch to commit to', default: 'main' },
        message: { type: 'string', description: 'Commit message' },
        files: {
          type: 'array',
          description: 'Files to commit',
          items: {
            type: 'object',
            properties: {
              path: { type: 'string', description: 'File path in repo' },
              content: { type: 'string', description: 'File content' },
              delete: { type: 'boolean', description: 'Set true to delete file' },
            },
            required: ['path'],
          },
        },
        createBranch: {
          type: 'boolean',
          description: 'Create branch if it does not exist',
          default: false,
        },
        baseBranch: {
          type: 'string',
          description: 'Base branch for new branch creation',
          default: 'main',
        },
        createPr: {
          type: 'boolean',
          description: 'Create a pull request after committing',
          default: false,
        },
        prTitle: { type: 'string', description: 'PR title (required if createPr is true)' },
        prBody: { type: 'string', description: 'PR body/description' },
        prLabels: {
          type: 'array',
          items: { type: 'string' },
          description: 'Labels to apply to the PR',
        },
      },
      required: ['owner', 'repo', 'message', 'files'],
    },
  },
  {
    name: 'repo_read_file',
    description: 'Read a file from a repository',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        path: { type: 'string', description: 'File path in repo' },
        ref: { type: 'string', description: 'Branch, tag, or commit SHA', default: 'main' },
      },
      required: ['owner', 'repo', 'path'],
    },
  },
  {
    name: 'repo_list_files',
    description: 'List files in a repository directory',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string' },
        repo: { type: 'string' },
        path: { type: 'string', description: 'Directory path in repo', default: '' },
        ref: { type: 'string', description: 'Branch, tag, or commit SHA', default: 'main' },
      },
      required: ['owner', 'repo'],
    },
  },

  // ========== Security Enforcement Tools ==========
  {
    name: 'security_enforce',
    description: 'Ensure Dependabot vulnerability alerts and automated security fixes are enabled on all managed repos (or a specific repo)',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repo owner (omit to enforce on all managed repos)' },
        repo: { type: 'string', description: 'Repo name (omit to enforce on all managed repos)' },
      },
    },
  },

  // ========== Autonomous Security Tools ==========
  {
    name: 'security_sweep',
    description: 'Autonomous security sweep: scans repos for CVEs, creates RFC issues with ITIL-formatted change records, and dispatches a GitHub Actions workflow to fix vulnerabilities and create PRs — all in one call. Supports chunked execution: set chunkSize to process a subset per call and call again with resume:true to continue.',
    inputSchema: {
      type: 'object',
      properties: {
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'all'],
          default: 'critical',
          description: 'Minimum severity to include',
        },
        repos: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific repos to sweep (owner/repo). Omit to sweep all managed repos.',
        },
        dryRun: {
          type: 'boolean',
          default: false,
          description: 'Scan and report only, do not create issues or dispatch fixes',
        },
        skipRfc: {
          type: 'boolean',
          default: false,
          description: 'Skip RFC issue creation (dispatch fix workflow directly)',
        },
        chunkSize: {
          type: 'number',
          description: 'Max repos to process per call. Omit to process all in one shot. When set, a cursor is persisted and the next call with resume:true continues where this left off.',
        },
        resume: {
          type: 'boolean',
          default: false,
          description: 'Resume a previously chunked sweep from the saved cursor. Ignores repos/severity/skipRfc (carried from the original call).',
        },
        skipRecentHours: {
          type: 'number',
          description: 'Skip repos swept within this many hours (default: no skip). Useful for polling fallback — set to 6 to avoid re-scanning repos touched in the last 6h.',
        },
      },
    },
  },

  // ========== Code Quality Tools ==========
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

  // ========== Report Tools ==========
  {
    name: 'report_generate',
    description: 'Generate compliance and security reports from git-steer state data. Templates: executive-summary, change-records, vulnerability-report, full-audit.',
    inputSchema: {
      type: 'object',
      properties: {
        template: {
          type: 'string',
          enum: ['executive-summary', 'change-records', 'vulnerability-report', 'full-audit'],
          default: 'executive-summary',
        },
        dateRange: {
          type: 'object',
          properties: {
            start: { type: 'string', description: 'ISO date string (YYYY-MM-DD)' },
            end: { type: 'string', description: 'ISO date string (YYYY-MM-DD)' },
          },
        },
        format: {
          type: 'string',
          enum: ['markdown', 'json'],
          default: 'markdown',
        },
        commitToRepo: {
          type: 'boolean',
          default: false,
          description: 'Commit report to state repo reports/ directory',
        },
      },
    },
  },

  // ========== Dashboard Tools ==========
  {
    name: 'dashboard_generate',
    description: 'Generate a static analytics dashboard with SVG charts showing security metrics, MTTR, severity breakdown, and repo risk scores. Deploys to GitHub Pages.',
    inputSchema: {
      type: 'object',
      properties: {
        repo: {
          type: 'string',
          description: 'Filter metrics to a specific repo (owner/repo)',
        },
        dateRange: {
          type: 'object',
          properties: {
            start: { type: 'string' },
            end: { type: 'string' },
          },
        },
      },
    },
  },

  // ========== Code Review Tools ==========
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

export class MCPServer {
  private server: Server;
  private github: GitHubClient;
  private state: StateManager;
  private config: MCPServerConfig;
  private rateLimitCache: RateLimitSnapshot | null = null;
  private rateLimitTimer: ReturnType<typeof setInterval> | null = null;
  private httpServer: import('http').Server | null = null;
  // Active transports keyed by session ID (HTTP mode only)
  private transports: Record<string, SSEServerTransport | StreamableHTTPServerTransport> = {};

  constructor(config: MCPServerConfig) {
    this.config = config;
    this.github = config.github;
    this.state = config.state;

    this.server = new Server(
      {
        name: 'git-steer',
        version: VERSION,
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: TOOLS,
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await this.executeTool(name, args || {});

        // Snapshot rate limit telemetry accumulated during this tool call
        const throttle = this.github.getAndResetThrottleStats();
        const coreRl = this.rateLimitCache?.buckets['core'];

        // Log to audit
        this.state.addAuditEntry({
          action: name,
          repo: args?.repo ? `${args.owner}/${args.repo}` : undefined,
          result: 'success',
          details: args,
          rate_remaining: coreRl?.remaining,
          rate_reset: coreRl?.reset.toISOString(),
          is_secondary_limit_hit: throttle.isSecondaryLimitHit || undefined,
          retry_count: throttle.retryCount || undefined,
          backoff_ms: throttle.backoffMs || undefined,
        });

        return {
          content: [
            {
              type: 'text',
              text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error: any) {
        // Snapshot rate limit telemetry even on failure
        const throttle = this.github.getAndResetThrottleStats();
        const coreRl = this.rateLimitCache?.buckets['core'];

        // Log error to audit
        this.state.addAuditEntry({
          action: name,
          repo: args?.repo ? `${args.owner}/${args.repo}` : undefined,
          result: 'error',
          details: { error: error.message },
          rate_remaining: coreRl?.remaining,
          rate_reset: coreRl?.reset.toISOString(),
          is_secondary_limit_hit: throttle.isSecondaryLimitHit || undefined,
          retry_count: throttle.retryCount || undefined,
          backoff_ms: throttle.backoffMs || undefined,
        });

        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async executeTool(name: string, args: Record<string, any>): Promise<any> {
    switch (name) {
      // Repository tools
      case 'repo_list': {
        const repos = await this.github.listRepos();
        let filtered = repos;
        
        if (!args.includeArchived) {
          filtered = filtered.filter((r) => !r.archived);
        }
        
        if (args.filter) {
          // Escape regex special chars except *, then convert * to .*
          const escaped = args.filter
            .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*');
          const pattern = new RegExp(`^${escaped}$`, 'i');
          filtered = filtered.filter((r) => pattern.test(r.fullName));
        }
        
        return filtered;
      }

      case 'repo_create': {
        const repo = await this.github.createRepo({
          name: args.name,
          description: args.description,
          private: args.private,
          template: args.template,
        });

        if (args.addToManaged) {
          this.state.addManagedRepo({
            owner: repo.owner,
            name: repo.name,
            policies: ['default-branch-protection'],
          });
        }

        return repo;
      }

      case 'repo_archive': {
        await this.github.archiveRepo(args.owner, args.repo);
        return { archived: true, repo: `${args.owner}/${args.repo}` };
      }

      case 'repo_delete': {
        if (args.confirm !== `${args.owner}/${args.repo}`) {
          throw new Error(
            `Confirmation failed. Type "${args.owner}/${args.repo}" to confirm deletion.`
          );
        }
        await this.github.deleteRepo(args.owner, args.repo);
        this.state.removeManagedRepo(args.owner, args.repo);
        return { deleted: true, repo: `${args.owner}/${args.repo}` };
      }

      // Branch tools
      case 'branch_list': {
        const branches = await this.github.listBranchesGraphQL(args.owner, args.repo);
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

      case 'branch_protect': {
        let rules = args.customRules || {};
        
        if (args.policy && args.policy !== 'custom') {
          const policies = this.state.getPolicies();
          const policy = policies[args.policy];
          if (policy?.protection) {
            rules = {
              requiredReviews: policy.protection.required_reviews,
              dismissStaleReviews: policy.protection.dismiss_stale_reviews,
              requireCodeOwnerReviews: policy.protection.require_code_owner_reviews,
            };
          }
        }

        await this.github.protectBranch(args.owner, args.repo, args.branch, rules);
        return { protected: true, branch: args.branch, rules };
      }

      case 'branch_reap': {
        const branches = await this.github.listBranchesGraphQL(args.owner, args.repo);
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
          await this.github.deleteBranch(args.owner, args.repo, branch.name);
          deleted.push(branch.name);
        }

        return { deleted };
      }

      // Security tools
      case 'security_alerts': {
        const alerts = await this.github.getSecurityAlerts(args.owner, args.repo);
        
        if (args.severity && args.severity !== 'all') {
          return alerts.filter((a) => a.severity === args.severity);
        }
        
        return alerts;
      }

      case 'security_dismiss': {
        await this.github.dismissSecurityAlert(
          args.owner,
          args.repo,
          args.alertId,
          args.reason
        );
        return { dismissed: true, alertId: args.alertId };
      }

      case 'security_digest': {
        const managedRepos = this.state.getManagedRepos();
        const digest: Record<string, any[]> = {};

        // Fetch alerts in parallel, capped at readLimit (8 concurrent).
        await Promise.all(
          managedRepos
            .filter((repo) => repo.name !== '*')
            .map((repo) =>
              readLimit(async () => {
                try {
                  const alerts = await this.github.getSecurityAlerts(repo.owner, repo.name);
                  const filtered =
                    args.severity === 'all'
                      ? alerts
                      : alerts.filter((a) => a.severity === args.severity);
                  if (filtered.length > 0) {
                    digest[`${repo.owner}/${repo.name}`] = filtered;
                  }
                } catch {
                  // Skip repos we can't access
                }
              })
            )
        );

        return digest;
      }

      // State tools
      case 'steer_status': {
        // If cache is stale (>30 min) or missing, refresh inline
        const cacheAgeMs = this.rateLimitCache
          ? Date.now() - this.rateLimitCache.fetchedAt.getTime()
          : Infinity;
        if (cacheAgeMs > 30 * 60 * 1000) {
          await this.refreshRateLimit();
        }

        const rl = this.rateLimitCache;
        const rateLimitInfo = rl
          ? {
              buckets: Object.fromEntries(
                Object.entries(rl.buckets).map(([name, b]) => [
                  name,
                  {
                    remaining: b.remaining,
                    limit: b.limit,
                    percentRemaining: b.percentRemaining,
                    resetsAt: b.reset.toISOString(),
                  },
                ])
              ),
              fetchedAt: rl.fetchedAt.toISOString(),
              warnings: rl.warnings,
              hasWarnings: rl.warnings.length > 0,
            }
          : null;

        return {
          github: {
            authenticated: this.github.isAuthenticated(),
            rateLimit: rateLimitInfo,
          },
          state: {
            lastSync: this.state.getLastSync()?.toISOString(),
            dirty: this.state.isDirty(),
            managedRepos: this.state.getManagedRepos().length,
            scheduledJobs: this.state.getScheduledJobs().length,
          },
        };
      }

      case 'steer_sync': {
        await this.state.save();
        return { synced: true, timestamp: new Date().toISOString() };
      }

      case 'steer_logs': {
        let logs = this.state.getRecentAudit(args.limit || 20);
        
        if (args.action) {
          logs = logs.filter((l) => l.action === args.action);
        }
        
        return logs;
      }

      case 'config_show': {
        const section = args.section || 'all';
        const result: Record<string, any> = {};

        if (section === 'all' || section === 'repos') {
          result.repos = this.state.getManagedRepos();
        }
        if (section === 'all' || section === 'policies') {
          result.policies = this.state.getPolicies();
        }
        if (section === 'all' || section === 'schedules') {
          result.schedules = this.state.getScheduledJobs();
        }

        return result;
      }

      case 'config_add_repo': {
        this.state.addManagedRepo({
          owner: args.owner,
          name: args.name,
          policies: args.policies || [],
        });

        // Enable Dependabot on the newly onboarded repo
        if (args.name !== '*') {
          try {
            await this.github.enableVulnerabilityAlerts(args.owner, args.name);
            await this.github.enableAutomatedSecurityFixes(args.owner, args.name);
          } catch {
            // Non-fatal — repo may not support Dependabot
          }
        }

        return { added: true, repo: `${args.owner}/${args.name}`, dependabotEnabled: args.name !== '*' };
      }

      case 'config_remove_repo': {
        this.state.removeManagedRepo(args.owner, args.name);
        return { removed: true, repo: `${args.owner}/${args.name}` };
      }

      // Repository settings
      case 'repo_settings': {
        await this.github.updateRepoSettings(args.owner, args.repo, {
          description: args.settings?.description,
          homepage: args.settings?.homepage,
          private: args.settings?.private,
          has_issues: args.settings?.hasIssues,
          has_projects: args.settings?.hasProjects,
          has_wiki: args.settings?.hasWiki,
          default_branch: args.settings?.defaultBranch,
        });
        return { updated: true, repo: `${args.owner}/${args.repo}` };
      }

      // Actions tools
      case 'actions_workflows': {
        const workflows = await this.github.listWorkflows(args.owner, args.repo);
        return workflows;
      }

      case 'actions_trigger': {
        await this.github.triggerWorkflow(
          args.owner,
          args.repo,
          args.workflow,
          args.ref || 'main',
          args.inputs
        );
        return {
          triggered: true,
          workflow: args.workflow,
          ref: args.ref || 'main',
        };
      }

      case 'actions_secrets': {
        switch (args.action) {
          case 'list': {
            const secrets = await this.github.listSecrets(args.owner, args.repo);
            return secrets;
          }
          case 'set': {
            if (!args.name || !args.value) {
              throw new Error('name and value are required for setting a secret');
            }
            await this.github.setSecret(args.owner, args.repo, args.name, args.value);
            return { set: true, name: args.name };
          }
          case 'delete': {
            if (!args.name) {
              throw new Error('name is required for deleting a secret');
            }
            await this.github.deleteSecret(args.owner, args.repo, args.name);
            return { deleted: true, name: args.name };
          }
          default:
            throw new Error(`Unknown action: ${args.action}`);
        }
      }

      // Security workflow tools
      case 'security_scan': {
        const repos = args.repo === '*' || !args.repo
          ? await this.github.listRepos()
          : [{ owner: args.owner, name: args.repo, fullName: `${args.owner}/${args.repo}` }];

        const results: Record<string, any[]> = {};
        const severityOrder = ['critical', 'high', 'medium', 'low'];
        const minSeverityIndex = args.severity === 'all' ? 4 : severityOrder.indexOf(args.severity);

        // Fetch alerts in parallel, capped at readLimit (8 concurrent).
        await Promise.all(
          repos.map((repo) =>
            readLimit(async () => {
              try {
                const alerts = await this.github.getSecurityAlertsDetailed(
                  repo.owner || args.owner,
                  repo.name
                );
                const filtered = alerts.filter((a) => {
                  const idx = severityOrder.indexOf(a.severity);
                  return idx <= minSeverityIndex;
                });
                if (filtered.length > 0) {
                  results[repo.fullName || `${args.owner}/${repo.name}`] = filtered;
                }
              } catch {
                // Skip repos we can't access
              }
            })
          )
        );

        const summary = {
          reposScanned: repos.length,
          reposWithAlerts: Object.keys(results).length,
          totalAlerts: Object.values(results).flat().length,
          bySeverity: {
            critical: Object.values(results).flat().filter((a) => a.severity === 'critical').length,
            high: Object.values(results).flat().filter((a) => a.severity === 'high').length,
            medium: Object.values(results).flat().filter((a) => a.severity === 'medium').length,
            low: Object.values(results).flat().filter((a) => a.severity === 'low').length,
          },
          alerts: results,
        };

        return summary;
      }

      case 'security_fix_pr': {
        // First, check what vulnerabilities exist
        const alerts = await this.github.getSecurityAlertsDetailed(args.owner, args.repo);
        const severityOrder = ['critical', 'high', 'medium', 'low'];
        const minSeverityIndex = args.severity === 'all' ? 4 : severityOrder.indexOf(args.severity || 'critical');

        const toFix = alerts.filter((a) => {
          const idx = severityOrder.indexOf(a.severity);
          return idx <= minSeverityIndex && a.fixVersion;
        });

        if (toFix.length === 0) {
          return {
            message: 'No fixable vulnerabilities found at the specified severity level',
            severity: args.severity || 'critical',
            totalAlerts: alerts.length,
          };
        }

        if (args.dryRun) {
          return {
            dryRun: true,
            wouldFix: toFix.length,
            vulnerabilities: toFix.map((a) => ({
              package: a.package,
              severity: a.severity,
              cve: a.cve,
              currentVersion: a.currentVersion,
              fixVersion: a.fixVersion,
              manifestPath: a.manifestPath,
            })),
            note: 'Use dryRun: false to dispatch a GitHub Actions workflow that will fix these vulnerabilities',
          };
        }

        // Dispatch the security-fix workflow in git-steer repo
        // This runs in ephemeral cloud compute - no local code needed!
        const targetRepo = `${args.owner}/${args.repo}`;
        const result = await this.github.dispatchSecurityFix(targetRepo, {
          severity: args.severity || 'critical',
          dryRun: false,
          jobId: `fix-${args.repo}-${Date.now()}`,
        });

        // Log the dispatch
        this.state.addAuditEntry({
          action: 'security_fix_dispatched',
          repo: targetRepo,
          result: 'success',
          details: {
            jobId: result.jobId,
            severity: args.severity || 'critical',
            vulnerabilitiesFound: toFix.length,
          },
        });

        return {
          success: true,
          mode: 'workflow_dispatch',
          message: 'Security fix workflow dispatched to GitHub Actions',
          jobId: result.jobId,
          targetRepo,
          severity: args.severity || 'critical',
          vulnerabilitiesFound: toFix.length,
          note: 'The fix is running in ephemeral cloud compute. Use workflow_status to check progress.',
          vulnerabilities: toFix.map((a) => ({
            package: a.package,
            severity: a.severity,
            cve: a.cve,
            fixVersion: a.fixVersion,
          })),
        };
      }

      case 'workflow_status': {
        const workflowFile = args.workflow === 'heartbeat' ? 'heartbeat.yml' : 'security-fix.yml';
        const runs = await this.github.getWorkflowRuns('ry-ops', 'git-steer', workflowFile, {
          perPage: args.limit || 5,
        });

        return {
          workflow: args.workflow || 'security-fix',
          runs: runs.map((r) => ({
            id: r.id,
            status: r.status,
            conclusion: r.conclusion,
            createdAt: r.createdAt,
            url: r.htmlUrl,
          })),
        };
      }

      // ===== Security Enforcement =====
      case 'security_enforce': {
        let targetRepos: Array<{ owner: string; name: string }>;

        if (args.owner && args.repo) {
          targetRepos = [{ owner: args.owner, name: args.repo }];
        } else {
          const managed = this.state.getManagedRepos();
          if (managed.length === 0) {
            const allRepos = await this.github.listRepos();
            targetRepos = allRepos.map((r) => ({ owner: r.owner, name: r.name }));
          } else {
            targetRepos = managed
              .filter((r) => r.name !== '*')
              .map((r) => ({ owner: r.owner, name: r.name }));
          }
        }

        const results: Array<{
          repo: string;
          alerts: string;
          autoFix: string;
        }> = [];

        for (const repo of targetRepos) {
          const repoFullName = `${repo.owner}/${repo.name}`;
          let alertsStatus = 'unknown';
          let autoFixStatus = 'unknown';

          try {
            await this.github.enableVulnerabilityAlerts(repo.owner, repo.name);
            alertsStatus = 'enabled';
          } catch (error: any) {
            alertsStatus = `failed: ${error.message}`;
          }

          try {
            await this.github.enableAutomatedSecurityFixes(repo.owner, repo.name);
            autoFixStatus = 'enabled';
          } catch (error: any) {
            autoFixStatus = `failed: ${error.message}`;
          }

          results.push({ repo: repoFullName, alerts: alertsStatus, autoFix: autoFixStatus });
        }

        return {
          enforced: results.length,
          results,
        };
      }

      // ===== Autonomous Security Sweep =====
      case 'security_sweep': {
        const severityOrder = ['critical', 'high', 'medium', 'low'];

        // ── Cursor / resume logic ─────────────────────────────────────────────
        let cursor = this.state.getSweepCursor();
        let allRepos: Array<{ owner: string; name: string; fullName: string }>;
        let minSev: string;
        let effectiveSkipRfc: boolean;
        let effectiveDryRun: boolean;

        if (args.resume && cursor) {
          // Continuing a previous chunked sweep — carry params from cursor
          allRepos = cursor.repos;
          minSev = cursor.params.severity;
          effectiveSkipRfc = cursor.params.skipRfc;
          effectiveDryRun = cursor.params.dryRun;
        } else {
          // Fresh sweep — resolve full repo list
          minSev = args.severity || 'critical';
          effectiveSkipRfc = args.skipRfc || false;
          effectiveDryRun = args.dryRun || false;

          if (args.repos && args.repos.length > 0) {
            allRepos = args.repos.map((r: string) => {
              const [owner, name] = r.split('/');
              return { owner, name, fullName: r };
            });
          } else {
            const managed = this.state.getManagedRepos();
            if (managed.length === 0) {
              const fetched = await this.github.listRepos();
              allRepos = fetched.map((r) => ({ owner: r.owner, name: r.name, fullName: r.fullName }));
            } else {
              allRepos = managed
                .filter((r) => r.name !== '*')
                .map((r) => ({ owner: r.owner, name: r.name, fullName: `${r.owner}/${r.name}` }));
            }
          }

          // Start a new cursor if chunkSize is requested
          if (args.chunkSize) {
            cursor = {
              repos: allRepos,
              nextIndex: 0,
              startedAt: new Date().toISOString(),
              params: { severity: minSev, skipRfc: effectiveSkipRfc, dryRun: effectiveDryRun },
            };
          } else {
            // Full run — clear any stale cursor
            this.state.clearSweepCursor();
            cursor = null;
          }
        }

        const minSevIndex = minSev === 'all' ? 4 : severityOrder.indexOf(minSev);

        // ── Determine the slice to process this call ──────────────────────────
        const startIndex = cursor?.nextIndex ?? 0;
        const chunkSize = args.chunkSize ?? allRepos.length;
        let slicedRepos = allRepos.slice(startIndex, startIndex + chunkSize);

        // ── Skip recently-swept repos (polling fallback) ───────────────────────
        if (args.skipRecentHours && args.skipRecentHours > 0) {
          const cutoff = Date.now() - args.skipRecentHours * 60 * 60 * 1000;
          slicedRepos = slicedRepos.filter((r) => {
            const last = this.state.getLastSweptAt(r.fullName);
            return !last || new Date(last).getTime() < cutoff;
          });
        }

        let targetRepos = slicedRepos;

        // Scan each repo
        const sweepResults: Array<{
          repo: string;
          owner: string;
          name: string;
          dependabotAlerts: any[];
          codeScanningAlerts: any[];
          issueNumber?: number;
          issueUrl?: string;
        }> = [];

        // Fetch all Dependabot alerts for the full repo batch in ONE GraphQL
        // round-trip, then fetch code-scanning alerts in parallel via REST
        // (no GraphQL equivalent exists). This replaces 2N REST calls with
        // 1 GraphQL + N REST calls.
        const [vulnBatch, codeScanMap] = await Promise.all([
          // Single GraphQL call for all repos' vulnerability alerts
          this.github.getVulnerabilityAlertsBatch(targetRepos),
          // Code-scanning: still REST, still parallelised with readLimit
          (async () => {
            const map: Record<string, any[]> = {};
            await Promise.all(
              targetRepos.map((repo) =>
                readLimit(async () => {
                  try {
                    map[repo.fullName] = await this.github.getCodeScanningAlerts(repo.owner, repo.name);
                  } catch {
                    map[repo.fullName] = [];
                  }
                })
              )
            );
            return map;
          })(),
        ]);

        for (const repo of targetRepos) {
          const depAlerts = vulnBatch[repo.fullName] ?? [];
          const codeAlerts = codeScanMap[repo.fullName] ?? [];

          const filteredDep = depAlerts.filter((a) => {
            const idx = severityOrder.indexOf(a.severity);
            return idx >= 0 && idx <= minSevIndex;
          });

          const filteredCode = codeAlerts.filter((a) => {
            const idx = severityOrder.indexOf(a.rule.severity);
            return idx >= 0 && idx <= minSevIndex;
          });

          if (filteredDep.length > 0 || filteredCode.length > 0) {
            sweepResults.push({
              repo: repo.fullName,
              owner: repo.owner,
              name: repo.name,
              dependabotAlerts: filteredDep,
              codeScanningAlerts: filteredCode,
            });
          }
        }

        if (effectiveDryRun) {
          return {
            dryRun: true,
            reposScanned: targetRepos.length,
            reposWithFindings: sweepResults.length,
            findings: sweepResults.map((r) => ({
              repo: r.repo,
              dependabotAlerts: r.dependabotAlerts.length,
              codeScanningAlerts: r.codeScanningAlerts.length,
              vulnerabilities: r.dependabotAlerts.map((a) => ({
                cve: a.cve,
                package: a.package,
                severity: a.severity,
                fixVersion: a.fixVersion,
              })),
            })),
          };
        }

        // Create RFC issues and track state
        const jobId = `sweep-${Date.now()}`;
        const workflowTargets: Array<{ owner: string; repo: string; issueNumber: number; vulnerabilities: any[] }> = [];

        // Create RFC issues in parallel, capped at writeLimit (2 concurrent) to avoid
        // triggering GitHub's secondary rate limit on back-to-back write bursts.
        await Promise.all(
          sweepResults.map((result) =>
            writeLimit(async () => {
              if (!effectiveSkipRfc) {
                // Ensure labels exist (parallelise the 5 label checks within one slot)
                const maxSeverity = result.dependabotAlerts.reduce((max, a) => {
                  const idx = severityOrder.indexOf(a.severity);
                  const maxIdx = severityOrder.indexOf(max);
                  return idx < maxIdx ? a.severity : max;
                }, 'low');

                await Promise.all([
                  this.github.ensureLabel(result.owner, result.name, 'security', 'd73a4a', 'Security vulnerability'),
                  this.github.ensureLabel(result.owner, result.name, 'rfc', '0075ca', 'Request for Change'),
                  this.github.ensureLabel(result.owner, result.name, 'dependencies', '0075ca', 'Dependency updates'),
                  this.github.ensureLabel(result.owner, result.name, 'automated', 'bfd4f2', 'Created by automation'),
                  this.github.ensureLabel(result.owner, result.name, `severity:${maxSeverity}`, maxSeverity === 'critical' ? 'b60205' : maxSeverity === 'high' ? 'ff9800' : 'fbca04', `${maxSeverity} severity`),
                ]);

                // Build RFC issue body
                const cveTable = result.dependabotAlerts.map((a) =>
                  `| ${a.cve || 'N/A'} | ${a.package} | ${a.severity.toUpperCase()} | ${a.currentVersion} | ${a.fixVersion || 'N/A'} |`
                ).join('\n');

                const issueBody = `## RFC: Security Vulnerability Remediation

**Repository:** ${result.repo}
**Severity:** ${maxSeverity.toUpperCase()}
**Date:** ${new Date().toISOString().split('T')[0]}
**Generated by:** git-steer autonomous security sweep

### Vulnerabilities

| CVE | Package | Severity | Current | Fix Version |
|-----|---------|----------|---------|-------------|
${cveTable}

${result.codeScanningAlerts.length > 0 ? `### Code Scanning Alerts

| Rule | Severity | File | Line |
|------|----------|------|------|
${result.codeScanningAlerts.map((a) => `| ${a.rule.id} | ${a.rule.severity} | ${a.location.path} | ${a.location.startLine} |`).join('\n')}
` : ''}
### Change Plan

1. Update vulnerable dependencies to patched versions
2. Run automated tests to verify compatibility
3. Create PR with fixes
4. Merge after review

### Risk Assessment

- **Impact of not fixing:** Potential security breach via known CVEs
- **Impact of fix:** Dependency version bumps, low risk of breakage
- **Rollback plan:** Revert PR if tests fail

---

*This RFC was auto-generated by git-steer. A fix PR will be created automatically.*`;

                const issue = await this.github.createIssue(result.owner, result.name, {
                  title: `[RFC] Security: ${result.dependabotAlerts.length} vulnerabilities (${maxSeverity})`,
                  body: issueBody,
                  labels: ['security', 'rfc', 'automated', `severity:${maxSeverity}`],
                });

                result.issueNumber = issue.number;
                result.issueUrl = issue.url;

                // Track RFC in state
                this.state.addRfc({
                  repo: result.repo,
                  issueNumber: issue.number,
                  issueUrl: issue.url,
                  severity: maxSeverity,
                  vulnerabilities: result.dependabotAlerts.map((a) => ({
                    cve: a.cve,
                    package: a.package,
                    severity: a.severity,
                    fixVersion: a.fixVersion,
                  })),
                  status: 'open',
                });
              }

              workflowTargets.push({
                owner: result.owner,
                repo: result.name,
                issueNumber: result.issueNumber || 0,
                vulnerabilities: result.dependabotAlerts,
              });
            })
          )
        );

        // Dispatch security-sweep workflow
        if (workflowTargets.length > 0) {
          await this.github.triggerWorkflow(
            'ry-ops',
            'git-steer',
            'security-sweep.yml',
            'main',
            {
              target_repos: JSON.stringify(workflowTargets),
              severity: minSev,
              job_id: jobId,
              dry_run: 'false',
            }
          );
        }

        // ── Record last-swept timestamp for each processed repo ───────────────
        const sweepTs = new Date().toISOString();
        for (const r of targetRepos) {
          this.state.setLastSweptAt(r.fullName, sweepTs);
        }

        // ── Advance or clear cursor ───────────────────────────────────────────
        const nextIndex = startIndex + chunkSize;
        const hasMore = cursor !== null && nextIndex < allRepos.length;
        if (hasMore && cursor) {
          this.state.setSweepCursor({ ...cursor, nextIndex });
        } else {
          this.state.clearSweepCursor();
        }

        return {
          success: true,
          jobId,
          reposScanned: targetRepos.length,
          reposWithFindings: sweepResults.length,
          rfcsCreated: effectiveSkipRfc ? 0 : sweepResults.length,
          workflowDispatched: workflowTargets.length > 0,
          // Pagination metadata
          pagination: cursor !== null
            ? {
                chunked: true,
                processedRange: [startIndex, Math.min(nextIndex, allRepos.length) - 1],
                totalRepos: allRepos.length,
                hasMore,
                nextIndex: hasMore ? nextIndex : null,
              }
            : undefined,
          repos: sweepResults.map((r) => ({
            repo: r.repo,
            dependabotAlerts: r.dependabotAlerts.length,
            codeScanningAlerts: r.codeScanningAlerts.length,
            issueNumber: r.issueNumber,
            issueUrl: r.issueUrl,
          })),
        };
      }

      // ===== Code Quality Sweep =====
      case 'code_quality_sweep': {
        const jobId = `quality-${Date.now()}`;

        // Ensure labels exist on target repo for issue creation
        if (args.createIssues) {
          await this.github.ensureLabel(args.owner, args.repo, 'code-quality', '5319e7', 'Code quality findings');
          await this.github.ensureLabel(args.owner, args.repo, 'automated', 'bfd4f2', 'Created by automation');
        }

        // Determine tools to use
        let tools = args.tools || ['auto'];
        if (tools.includes('auto')) {
          // Auto-detect from repo files
          const files = await this.github.listFiles(args.owner, args.repo, '');
          const fileNames = files.map((f) => f.name);
          tools = [];
          if (fileNames.includes('package.json') || fileNames.includes('tsconfig.json')) tools.push('eslint');
          if (fileNames.includes('pyproject.toml') || fileNames.includes('requirements.txt') || fileNames.includes('setup.py')) {
            tools.push('ruff', 'bandit');
          }
          if (fileNames.includes('go.mod')) tools.push('gosec');
          if (tools.length === 0) tools = ['eslint']; // fallback
        }

        // Dispatch code-quality workflow
        await this.github.triggerWorkflow(
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

      // ===== Report Generation =====
      case 'report_generate': {
        const template = args.template || 'executive-summary';
        const dateRange = args.dateRange;
        const format = args.format || 'markdown';

        const metrics = this.state.getMetrics(dateRange);
        const rfcs = this.state.getRfcs();
        const quality = this.state.getQualityResults();

        const report = generateReport(template, { metrics, rfcs, quality, dateRange });

        if (format === 'json') {
          return { template, metrics, rfcs: rfcs.length, qualityResults: quality.length };
        }

        // Optionally commit to state repo
        if (args.commitToRepo) {
          const managedRepos = this.state.getManagedRepos();
          const stateRepoName = 'git-steer-state';
          const owner = managedRepos[0]?.owner || 'ry-ops';
          const fileName = `reports/${template}-${new Date().toISOString().split('T')[0]}.md`;

          await this.github.updateFileContent(
            owner,
            stateRepoName,
            fileName,
            report,
            `Add ${template} report for ${new Date().toISOString().split('T')[0]}`
          );

          return { report, committed: true, path: fileName };
        }

        return { report };
      }

      // ===== Dashboard Generation =====
      case 'dashboard_generate': {
        const dateRange = args.dateRange;
        const metrics = this.state.getMetrics(dateRange);
        const rfcs = this.state.getRfcs(args.repo ? { repo: args.repo } : undefined);
        const quality = this.state.getQualityResults(args.repo ? { repo: args.repo } : undefined);

        const html = generateDashboardHtml({ metrics, rfcs, quality, dateRange });

        // Deploy to gh-pages branch of state repo
        const owner = 'ry-ops';
        const stateRepo = 'git-steer-state';

        const commitResult = await this.github.commitFiles(owner, stateRepo, {
          branch: 'gh-pages',
          message: `Update dashboard ${new Date().toISOString()}`,
          files: [{ path: 'index.html', content: html }],
          createBranch: true,
          baseBranch: 'main',
        });

        return {
          success: true,
          dashboardUrl: `https://${owner}.github.io/${stateRepo}/`,
          commitSha: commitResult.sha,
          metrics: {
            totalCves: metrics.totalCves,
            fixedCves: metrics.fixedCves,
            fixRate: Math.round(metrics.fixRate * 100) + '%',
            avgMttr: Math.round(metrics.avgMttr) + ' hours',
          },
        };
      }

      // File operation tools
      case 'repo_commit': {
        if (!args.files || args.files.length === 0) {
          throw new Error('No files specified');
        }

        // Validate files have content (unless deleting)
        for (const file of args.files) {
          if (!file.delete && file.content === undefined) {
            throw new Error(`File ${file.path} has no content`);
          }
        }

        const branch = args.branch || 'main';
        const result = await this.github.commitFiles(args.owner, args.repo, {
          branch,
          message: args.message,
          files: args.files.map((f: any) => ({
            path: f.path,
            content: f.content || '',
            delete: f.delete,
          })),
          createBranch: args.createBranch,
          baseBranch: args.baseBranch,
        });

        let pr = null;
        if (args.createPr && branch !== 'main' && branch !== 'master') {
          if (!args.prTitle) {
            throw new Error('prTitle is required when createPr is true');
          }

          pr = await this.github.createPullRequest(args.owner, args.repo, {
            title: args.prTitle,
            body: args.prBody || '',
            head: branch,
            base: args.baseBranch || 'main',
            labels: args.prLabels,
          });
        }

        return {
          success: true,
          commit: {
            sha: result.sha,
            url: result.url,
          },
          branch,
          filesCommitted: args.files.length,
          pr: pr ? { number: pr.number, url: pr.url } : null,
        };
      }

      case 'repo_read_file': {
        const file = await this.github.getFile(
          args.owner,
          args.repo,
          args.path,
          args.ref
        );

        if (!file) {
          return {
            found: false,
            path: args.path,
            message: 'File not found',
          };
        }

        return {
          found: true,
          path: args.path,
          content: file.content,
          sha: file.sha,
        };
      }

      case 'repo_list_files': {
        const files = await this.github.listFiles(
          args.owner,
          args.repo,
          args.path || '',
          args.ref
        );

        return {
          path: args.path || '/',
          files: files,
          count: files.length,
        };
      }

      // Code review tool
      case 'code_review': {
        // Find coderabbit CLI
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

        // Build command
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

        // Verify it's a git repo
        const gitDir = join(cwd, '.git');
        if (!existsSync(gitDir)) {
          throw new Error(`Not a git repository: ${cwd}`);
        }

        try {
          const output = execFileSync(cmdParts[0], cmdParts.slice(1), {
            cwd,
            encoding: 'utf-8',
            maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large reviews
            timeout: 300000, // 5 minute timeout
          });

          return {
            success: true,
            cwd,
            reviewType: args.type || 'all',
            base: args.base || null,
            review: output,
          };
        } catch (error: any) {
          // CodeRabbit may exit with non-zero even on success (e.g., findings)
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

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async refreshRateLimit(): Promise<void> {
    try {
      this.rateLimitCache = await this.github.getRateLimit();
      if (this.rateLimitCache.warnings.length > 0) {
        console.warn(`[git-steer] Rate limit warnings: ${this.rateLimitCache.warnings.join(' | ')}`);
      }
    } catch {
      // Non-fatal — keep existing cache if refresh fails
    }
  }

  async start(): Promise<void> {
    // Fetch rate limits at startup and refresh every 30 minutes
    await this.refreshRateLimit();
    this.rateLimitTimer = setInterval(() => void this.refreshRateLimit(), 30 * 60 * 1000);

    if (this.config.transport === 'stdio') {
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
    } else {
      await this.startHttpServer(this.config.port ?? 3333);
    }
  }

  private async startHttpServer(port: number): Promise<void> {
    // createMcpExpressApp returns an Express app pre-wired with:
    //   - express.json() body parser
    //   - localhost-only DNS rebinding protection
    const app = createMcpExpressApp();

    // ── Streamable HTTP transport (MCP protocol 2025-11-25) ──────────────────
    // Single endpoint handles GET (SSE stream), POST (messages), DELETE (close)
    app.all('/mcp', async (req: IncomingMessage & { body?: unknown }, res: ServerResponse) => {
      try {
        const sessionId = (req as any).headers?.['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (sessionId && this.transports[sessionId] instanceof StreamableHTTPServerTransport) {
          transport = this.transports[sessionId] as StreamableHTTPServerTransport;
        } else if (!sessionId && (req as any).method === 'POST' && isInitializeRequest((req as any).body)) {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sid) => {
              this.transports[sid] = transport;
            },
          });
          transport.onclose = () => {
            const sid = transport.sessionId;
            if (sid) delete this.transports[sid];
          };
          await this.server.connect(transport);
        } else {
          (res as any).status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: no valid session' },
            id: null,
          });
          return;
        }

        await transport.handleRequest(req as any, res as any, (req as any).body);
      } catch (err) {
        console.error('[git-steer] HTTP transport error:', err);
        if (!(res as any).headersSent) {
          (res as any).status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          });
        }
      }
    });

    // ── Legacy SSE transport (MCP protocol 2024-11-05) ───────────────────────
    // Kept for backwards compatibility with older MCP clients
    app.get('/sse', async (_req: IncomingMessage, res: ServerResponse) => {
      const transport = new SSEServerTransport('/messages', res as any);
      this.transports[transport.sessionId] = transport;
      (res as any).on('close', () => delete this.transports[transport.sessionId]);
      await this.server.connect(transport);
    });

    app.post('/messages', async (req: IncomingMessage & { body?: unknown }, res: ServerResponse) => {
      const sessionId = (req as any).query?.sessionId as string | undefined;
      const transport = sessionId ? this.transports[sessionId] : undefined;
      if (transport instanceof SSEServerTransport) {
        await transport.handlePostMessage(req as any, res as any, (req as any).body);
      } else {
        (res as any).status(400).send('No SSE transport found for sessionId');
      }
    });

    // ── Live dashboard ───────────────────────────────────────────────────────
    // Renders the security dashboard from current in-memory state on every request.
    // Same HTML as dashboard_generate() but served locally — no GitHub Pages needed.
    app.get('/dashboard', (_req: IncomingMessage, res: ServerResponse) => {
      try {
        const metrics = this.state.getMetrics();
        const rfcs = this.state.getRfcs();
        const quality = this.state.getQualityResults();
        const html = generateDashboardHtml({ metrics, rfcs, quality });
        (res as any).setHeader('Content-Type', 'text/html; charset=utf-8');
        (res as any).send(html);
      } catch (err) {
        console.error('[git-steer] Dashboard render error:', err);
        (res as any).status(500).send('Failed to render dashboard');
      }
    });

    // ── Health check ─────────────────────────────────────────────────────────
    app.get('/health', (_req: IncomingMessage, res: ServerResponse) => {
      (res as any).json({
        status: 'ok',
        version: VERSION,
        transport: 'http',
        activeSessions: Object.keys(this.transports).length,
        endpoints: {
          dashboard: '/dashboard',
          streamableHttp: '/mcp',
          legacySse: '/sse',
          legacyMessages: '/messages',
          health: '/health',
        },
      });
    });

    // Start listening
    await new Promise<void>((resolve, reject) => {
      this.httpServer = (app as any).listen(port, (err?: Error) => {
        if (err) return reject(err);
        console.log(`[git-steer] Portal listening on http://localhost:${port}`);
        console.log(`[git-steer]   Dashboard       : http://localhost:${port}/dashboard`);
        console.log(`[git-steer]   Streamable HTTP : http://localhost:${port}/mcp`);
        console.log(`[git-steer]   Legacy SSE      : http://localhost:${port}/sse`);
        console.log(`[git-steer]   Health          : http://localhost:${port}/health`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.rateLimitTimer) {
      clearInterval(this.rateLimitTimer);
      this.rateLimitTimer = null;
    }

    // Close all active HTTP transports
    for (const [sid, transport] of Object.entries(this.transports)) {
      try {
        await transport.close();
      } catch {
        // best-effort
      }
      delete this.transports[sid];
    }

    // Close HTTP server if running
    if (this.httpServer) {
      await new Promise<void>((resolve) => this.httpServer!.close(() => resolve()));
      this.httpServer = null;
    }

    await this.server.close();
  }
}
