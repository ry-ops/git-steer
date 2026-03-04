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
import { initGateway } from '../fabric/gateway.js';
import type { GatewayHandle } from '../fabric/gateway.js';
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
  gateway?: GatewayHandle;
}

const FABRIC_CVE_TOOLS: Tool[] = [
  // ========== Fabric Tools (via @git-fabric/cve) ==========
  {
    name: 'fabric_cve_scan',
    description: '[git-fabric] Scan managed repos for vulnerable dependencies via GitHub Advisory Database. Queues findings to state/cve-queue.jsonl.',
    inputSchema: {
      type: 'object',
      properties: {
        repos: {
          type: 'array',
          items: { type: 'string' },
          description: 'Repos to scan (owner/repo). Defaults to all managed repos.',
        },
        severity_threshold: {
          type: 'string',
          enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
          default: 'HIGH',
        },
        dry_run: { type: 'boolean', default: false },
      },
    },
  },
  {
    name: 'fabric_cve_enrich',
    description: '[git-fabric] Fetch enriched vulnerability details for a CVE from NVD. Returns severity, CVSS, NVD status, CWE, and references.',
    inputSchema: {
      type: 'object',
      properties: {
        cve_id: { type: 'string', description: 'CVE ID (e.g. CVE-2024-12345)' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'fabric_cve_triage',
    description: '[git-fabric] Process pending CVE queue entries: apply severity policy and open PRs. CRITICAL = confirmed PR, HIGH = draft PR.',
    inputSchema: {
      type: 'object',
      properties: {
        auto_pr_threshold: {
          type: 'string',
          enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
          default: 'HIGH',
        },
        max_prs_per_run: { type: 'number', default: 5 },
        dry_run: { type: 'boolean', default: false },
      },
    },
  },
  {
    name: 'fabric_cve_queue',
    description: '[git-fabric] List CVE queue entries filtered by status and severity.',
    inputSchema: {
      type: 'object',
      properties: {
        status: {
          type: 'string',
          enum: ['pending', 'pr_opened', 'skipped', 'error', 'all'],
          default: 'pending',
        },
        severity_min: {
          type: 'string',
          enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
          default: 'LOW',
        },
        repo: { type: 'string', description: 'Filter to a specific repo' },
        limit: { type: 'number', description: 'Max entries to return (default: 50)', default: 50 },
      },
    },
  },
  {
    name: 'fabric_cve_stats',
    description: '[git-fabric] CVE queue health dashboard: totals by status/severity, oldest pending, top repos.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'fabric_cve_compact',
    description: '[git-fabric] Compact the CVE queue by removing resolved entries older than the retention period.',
    inputSchema: {
      type: 'object',
      properties: {
        retention_days: {
          type: 'number',
          description: 'Days to retain resolved entries (default: 30)',
          default: 30,
        },
      },
    },
  },
];

const CORE_TOOLS: Tool[] = [
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

  // ========== PR Deduplication ==========
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

  // ========== OOMKill Remediation ==========
  {
    name: 'oomkill_detect',
    description: 'Detect pods that have been OOMKilled. Returns pods with OOMKill events, their current resource limits, and restart counts.',
    inputSchema: {
      type: 'object',
      properties: {
        namespace: { type: 'string', description: 'Kubernetes namespace to scan. Omit for all namespaces.' },
        min_restarts: { type: 'number', description: 'Minimum restart count to include (default: 3)', default: 3 },
      },
    },
  },
  {
    name: 'oomkill_remediate',
    description: 'Auto-bump resource limits for OOMKilled pods by creating a PR to the GitOps repo. Calculates new limits as a multiplier of current limits (default: 1.5x). Uses PR dedup to avoid duplicate remediation PRs.',
    inputSchema: {
      type: 'object',
      properties: {
        namespace: { type: 'string', description: 'Kubernetes namespace' },
        deployment: { type: 'string', description: 'Deployment name to remediate' },
        container: { type: 'string', description: 'Container name (default: first container)' },
        multiplier: { type: 'number', description: 'Memory limit multiplier (default: 1.5)', default: 1.5 },
        gitops_owner: { type: 'string', description: 'GitOps repo owner' },
        gitops_repo: { type: 'string', description: 'GitOps repo name' },
        manifest_path: { type: 'string', description: 'Path to the deployment manifest in the GitOps repo' },
        dry_run: { type: 'boolean', description: 'Preview changes without creating a PR', default: false },
      },
      required: ['namespace', 'deployment', 'gitops_owner', 'gitops_repo', 'manifest_path'],
    },
  },

  // ========== Certificate Renewal ==========
  {
    name: 'cert_check',
    description: 'Detect TLS certificates approaching expiration in the cluster. Checks cert-manager Certificate resources and returns certificates expiring within the threshold.',
    inputSchema: {
      type: 'object',
      properties: {
        namespace: { type: 'string', description: 'Kubernetes namespace to scan. Omit for all namespaces.' },
        expiry_days: { type: 'number', description: 'Alert threshold in days before expiry (default: 30)', default: 30 },
      },
    },
  },
  {
    name: 'cert_renew',
    description: 'Trigger certificate renewal for expiring certificates. Deletes the certificate Secret to force cert-manager to re-issue, or creates a PR to update certificate manifests.',
    inputSchema: {
      type: 'object',
      properties: {
        namespace: { type: 'string', description: 'Certificate namespace' },
        certificate_name: { type: 'string', description: 'cert-manager Certificate resource name' },
        method: { type: 'string', enum: ['force_renewal', 'gitops_pr'], description: 'Renewal method: force_renewal deletes the Secret; gitops_pr creates a PR with annotation bump', default: 'force_renewal' },
        gitops_owner: { type: 'string', description: 'GitOps repo owner (required for gitops_pr method)' },
        gitops_repo: { type: 'string', description: 'GitOps repo name (required for gitops_pr method)' },
        manifest_path: { type: 'string', description: 'Path to cert manifest (required for gitops_pr method)' },
      },
      required: ['namespace', 'certificate_name'],
    },
  },

  // ========== Slack Integration ==========
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

  // ========== Operational Metrics ==========
  {
    name: 'ops_metrics',
    description: 'Get operational metrics: alert frequency, mean time to remediation, auto-merge success rate, and PR dedup hit rate.',
    inputSchema: {
      type: 'object',
      properties: {
        period: { type: 'string', enum: ['24h', '7d', '30d', 'all'], default: '7d', description: 'Time period for metrics' },
      },
    },
  },

  // ========== Fabric Tools (via @git-fabric/git) ==========
  { name: 'fabric_git_list_repos', description: '[git-fabric] List repositories for an org or the authenticated user.', inputSchema: { type: 'object', properties: { org: { type: 'string', description: 'GitHub org name. Omit to list repos for the authenticated user.' } } } },
  { name: 'fabric_git_get_file', description: '[git-fabric] Get the content of a file from a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, path: { type: 'string', description: 'File path relative to repo root.' }, ref: { type: 'string', description: 'Branch, tag, or commit SHA.' } }, required: ['owner', 'repo', 'path'] } },
  { name: 'fabric_git_list_files', description: '[git-fabric] List files and directories at a path in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, path: { type: 'string', description: 'Directory path. Defaults to root.' }, ref: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'fabric_git_commit_files', description: '[git-fabric] Commit one or more files to a branch via the GitHub Git Data API.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, branch: { type: 'string' }, message: { type: 'string' }, files: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] } }, createBranch: { type: 'boolean' }, fromBranch: { type: 'string' } }, required: ['owner', 'repo', 'branch', 'message', 'files'] } },
  { name: 'fabric_git_list_commits', description: '[git-fabric] List recent commits on a branch.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, branch: { type: 'string' }, limit: { type: 'number', description: 'Max commits to return. Default: 20.' } }, required: ['owner', 'repo'] } },
  { name: 'fabric_git_get_commit', description: '[git-fabric] Get full details for a commit including changed files.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, sha: { type: 'string' } }, required: ['owner', 'repo', 'sha'] } },
  { name: 'fabric_git_compare_commits', description: '[git-fabric] Compare two refs to see divergence and changed files.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, base: { type: 'string' }, head: { type: 'string' } }, required: ['owner', 'repo', 'base', 'head'] } },
  { name: 'fabric_git_list_branches', description: '[git-fabric] List branches in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'fabric_git_create_branch', description: '[git-fabric] Create a new branch from an existing branch.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, branch: { type: 'string', description: 'New branch name.' }, fromBranch: { type: 'string', description: 'Source branch.' } }, required: ['owner', 'repo', 'branch'] } },
  { name: 'fabric_git_delete_branch', description: '[git-fabric] Delete a branch.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, branch: { type: 'string' } }, required: ['owner', 'repo', 'branch'] } },
  { name: 'fabric_git_list_pull_requests', description: '[git-fabric] List pull requests in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'PR state filter. Default: open.' } }, required: ['owner', 'repo'] } },
  { name: 'fabric_git_get_pull_request', description: '[git-fabric] Get full details for a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, number: { type: 'number' } }, required: ['owner', 'repo', 'number'] } },
  { name: 'fabric_git_create_pull_request', description: '[git-fabric] Open a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' }, body: { type: 'string' }, draft: { type: 'boolean' }, labels: { type: 'array', items: { type: 'string' } } }, required: ['owner', 'repo', 'title', 'head'] } },
  { name: 'fabric_git_merge_pull_request', description: '[git-fabric] Merge a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, number: { type: 'number' }, method: { type: 'string', enum: ['merge', 'squash', 'rebase'] }, commitTitle: { type: 'string' }, commitMessage: { type: 'string' } }, required: ['owner', 'repo', 'number'] } },
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
  // Fabric gateway (initialized in start())
  private gateway: GatewayHandle | null = null;

  constructor(config: MCPServerConfig) {
    this.config = config;
    this.github = config.github;
    this.state = config.state;
    this.gateway = config.gateway ?? null;

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
    // List available tools — fabric tools only when gateway is loaded
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.gateway?.available
        ? [...CORE_TOOLS, ...FABRIC_CVE_TOOLS]
        : CORE_TOOLS,
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

      // ===== PR Deduplication =====
      case 'pr_dedup_check': {
        const openPrs = await this.github.listPullRequests(args.owner, args.repo, { state: 'open' });
        const match = openPrs.find((pr) => pr.title.startsWith(args.title_prefix));

        this.state.addAuditEntry({
          action: 'pr_dedup_check',
          repo: `${args.owner}/${args.repo}`,
          result: match ? 'duplicate_found' : 'no_duplicate',
          details: { title_prefix: args.title_prefix, matchedPr: match?.number },
        });

        return match
          ? { duplicate: true, existing_pr: match }
          : { duplicate: false, existing_pr: null };
      }

      case 'pr_dedup_create': {
        const prefix = args.title_prefix || args.title.split(' — ')[0];
        const openPrs = await this.github.listPullRequests(args.owner, args.repo, { state: 'open' });
        const existing = openPrs.find((pr) => pr.title.startsWith(prefix));

        if (existing) {
          this.state.addAuditEntry({
            action: 'pr_dedup_create',
            repo: `${args.owner}/${args.repo}`,
            result: 'dedup_hit',
            details: { title_prefix: prefix, existingPr: existing.number },
          });

          // Notify Slack if configured
          const slackConfig = this.state.getCache('slack_config');
          if (slackConfig?.webhook_url && slackConfig?.notify_on?.pr_dedup_hit) {
            await this.sendSlackNotification(slackConfig.webhook_url, {
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

        const pr = await this.github.createPullRequest(args.owner, args.repo, {
          title: args.title,
          body: args.body || '',
          head: args.head,
          base: args.base || 'main',
          labels: args.labels,
        });

        this.state.addAuditEntry({
          action: 'pr_dedup_create',
          repo: `${args.owner}/${args.repo}`,
          result: 'created',
          details: { prNumber: pr.number, title: args.title },
        });

        // Notify Slack if configured
        const slackConfig = this.state.getCache('slack_config');
        if (slackConfig?.webhook_url && slackConfig?.notify_on?.pr_created) {
          await this.sendSlackNotification(slackConfig.webhook_url, {
            text: `📋 New PR opened in \`${args.owner}/${args.repo}\`\n<${pr.url}|#${pr.number} ${args.title}>`,
          });
        }

        return {
          created: true,
          dedup_hit: false,
          pr: { number: pr.number, url: pr.url },
        };
      }

      // ===== OOMKill Remediation =====
      case 'oomkill_detect': {
        const ns = args.namespace ? `-n ${args.namespace}` : '--all-namespaces';
        const minRestarts = args.min_restarts || 3;

        let output: string;
        try {
          output = execFileSync('kubectl', [
            'get', 'pods', ...(args.namespace ? ['-n', args.namespace] : ['--all-namespaces']),
            '-o', 'json',
          ], { encoding: 'utf8', timeout: 30_000 });
        } catch (e: any) {
          throw new Error(`kubectl failed: ${e.message}`);
        }

        const pods = JSON.parse(output);
        const oomPods: Array<{
          namespace: string;
          pod: string;
          container: string;
          restartCount: number;
          currentLimits: Record<string, string>;
          lastOOMKill: string | null;
          deployment: string | null;
        }> = [];

        for (const pod of pods.items) {
          const podNs = pod.metadata.namespace;
          const podName = pod.metadata.name;
          const ownerRef = pod.metadata.ownerReferences?.[0];
          const deployment = ownerRef?.kind === 'ReplicaSet'
            ? ownerRef.name.replace(/-[a-f0-9]+$/, '')
            : ownerRef?.name || null;

          for (const cs of pod.status?.containerStatuses || []) {
            if (cs.restartCount >= minRestarts && cs.lastState?.terminated?.reason === 'OOMKilled') {
              const container = pod.spec.containers.find((c: any) => c.name === cs.name);
              oomPods.push({
                namespace: podNs,
                pod: podName,
                container: cs.name,
                restartCount: cs.restartCount,
                currentLimits: container?.resources?.limits || {},
                lastOOMKill: cs.lastState.terminated.finishedAt || null,
                deployment,
              });
            }
          }
        }

        this.state.addAuditEntry({
          action: 'oomkill_detect',
          result: 'success',
          details: { oomPodsFound: oomPods.length, namespace: args.namespace || 'all' },
        });

        // Notify Slack if configured
        if (oomPods.length > 0) {
          const slackConfig = this.state.getCache('slack_config');
          if (slackConfig?.webhook_url && slackConfig?.notify_on?.oomkill_detected) {
            const podList = oomPods.slice(0, 5).map((p) => `• \`${p.namespace}/${p.pod}\` (${p.restartCount} restarts)`).join('\n');
            await this.sendSlackNotification(slackConfig.webhook_url, {
              text: `💥 OOMKill detected: ${oomPods.length} pod(s)\n${podList}${oomPods.length > 5 ? `\n...and ${oomPods.length - 5} more` : ''}`,
            });
          }
        }

        return { oomPods, total: oomPods.length };
      }

      case 'oomkill_remediate': {
        const multiplier = args.multiplier || 1.5;

        // Detect current OOMKill state for the deployment
        let podOutput: string;
        try {
          podOutput = execFileSync('kubectl', [
            'get', 'pods', '-n', args.namespace,
            '-l', `app=${args.deployment}`,
            '-o', 'json',
          ], { encoding: 'utf8', timeout: 30_000 });
        } catch {
          // Fallback: try with app.kubernetes.io/name label
          podOutput = execFileSync('kubectl', [
            'get', 'pods', '-n', args.namespace,
            '-l', `app.kubernetes.io/name=${args.deployment}`,
            '-o', 'json',
          ], { encoding: 'utf8', timeout: 30_000 });
        }

        const podData = JSON.parse(podOutput);
        if (podData.items.length === 0) {
          throw new Error(`No pods found for deployment ${args.deployment} in ${args.namespace}`);
        }

        // Find OOMKilled container
        const targetContainer = args.container || podData.items[0].spec.containers[0].name;
        const container = podData.items[0].spec.containers.find((c: any) => c.name === targetContainer);
        if (!container) {
          throw new Error(`Container ${targetContainer} not found`);
        }

        const currentMemLimit = container.resources?.limits?.memory || '256Mi';
        const currentCpuLimit = container.resources?.limits?.cpu || '500m';

        // Parse and bump memory limit
        const parseMemory = (mem: string): number => {
          if (mem.endsWith('Gi')) return parseFloat(mem) * 1024;
          if (mem.endsWith('Mi')) return parseFloat(mem);
          if (mem.endsWith('Ki')) return parseFloat(mem) / 1024;
          return parseFloat(mem) / (1024 * 1024); // bytes
        };

        const formatMemory = (mi: number): string => {
          if (mi >= 1024) return `${Math.round(mi / 1024 * 10) / 10}Gi`;
          return `${Math.round(mi)}Mi`;
        };

        const newMemLimit = formatMemory(parseMemory(currentMemLimit) * multiplier);
        const newMemRequest = formatMemory(parseMemory(currentMemLimit) * multiplier * 0.75);

        if (args.dry_run) {
          return {
            dry_run: true,
            deployment: args.deployment,
            namespace: args.namespace,
            container: targetContainer,
            current: { memory: currentMemLimit, cpu: currentCpuLimit },
            proposed: { memory: newMemLimit, memoryRequest: newMemRequest },
            multiplier,
          };
        }

        // Fetch the manifest from the gitops repo
        let manifestContent: string;
        try {
          const file = await this.github.getFileContent(args.gitops_owner, args.gitops_repo, args.manifest_path);
          manifestContent = file.content;
        } catch {
          throw new Error(`Cannot read manifest at ${args.manifest_path} in ${args.gitops_owner}/${args.gitops_repo}`);
        }

        // Update memory limits in the manifest (supports both YAML patterns)
        let updatedManifest = manifestContent;
        const memLimitPattern = new RegExp(`(memory:\\s*)${currentMemLimit.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g');
        updatedManifest = updatedManifest.replace(memLimitPattern, `$1${newMemLimit}`);

        if (updatedManifest === manifestContent) {
          // Try generic pattern: bump any memory limit in the file
          updatedManifest = manifestContent.replace(
            /(limits:\s*\n\s*memory:\s*)([\w.]+)/,
            `$1${newMemLimit}`
          );
        }

        // Create a branch and PR using dedup
        const branchName = `oomkill-remediate/${args.namespace}-${args.deployment}-${Date.now()}`;

        await this.github.commitFiles(args.gitops_owner, args.gitops_repo, {
          branch: branchName,
          message: `fix(oomkill): bump ${args.deployment} memory limit to ${newMemLimit}`,
          files: [{ path: args.manifest_path, content: updatedManifest }],
          createBranch: true,
          baseBranch: 'main',
        });

        // Use dedup to create the PR
        const prefix = `[OOMKill] ${args.namespace}/${args.deployment}`;
        const openPrs = await this.github.listPullRequests(args.gitops_owner, args.gitops_repo, { state: 'open' });
        const existingPr = openPrs.find((pr) => pr.title.startsWith(prefix));

        if (existingPr) {
          this.state.addAuditEntry({
            action: 'oomkill_remediate',
            repo: `${args.gitops_owner}/${args.gitops_repo}`,
            result: 'dedup_hit',
            details: { deployment: args.deployment, existingPr: existingPr.number },
          });
          return { created: false, dedup_hit: true, existing_pr: existingPr };
        }

        const pr = await this.github.createPullRequest(args.gitops_owner, args.gitops_repo, {
          title: `${prefix} — bump memory ${currentMemLimit} → ${newMemLimit}`,
          body: `## OOMKill Remediation\n\n**Deployment:** \`${args.namespace}/${args.deployment}\`\n**Container:** \`${targetContainer}\`\n**Current limit:** ${currentMemLimit}\n**New limit:** ${newMemLimit} (${multiplier}x)\n**New request:** ${newMemRequest}\n\n_Auto-generated by git-steer oomkill_remediate_`,
          head: branchName,
          base: 'main',
          labels: ['oomkill', 'auto-remediation'],
        });

        this.state.addAuditEntry({
          action: 'oomkill_remediate',
          repo: `${args.gitops_owner}/${args.gitops_repo}`,
          result: 'pr_created',
          details: { deployment: args.deployment, prNumber: pr.number, oldLimit: currentMemLimit, newLimit: newMemLimit },
        });

        return {
          created: true,
          pr: { number: pr.number, url: pr.url },
          changes: {
            deployment: args.deployment,
            container: targetContainer,
            oldLimit: currentMemLimit,
            newLimit: newMemLimit,
            multiplier,
          },
        };
      }

      // ===== Certificate Renewal =====
      case 'cert_check': {
        const expiryDays = args.expiry_days || 30;
        const now = new Date();
        const threshold = new Date(now.getTime() + expiryDays * 24 * 60 * 60 * 1000);

        let certOutput: string;
        try {
          certOutput = execFileSync('kubectl', [
            'get', 'certificates',
            ...(args.namespace ? ['-n', args.namespace] : ['--all-namespaces']),
            '-o', 'json',
          ], { encoding: 'utf8', timeout: 30_000 });
        } catch (e: any) {
          throw new Error(`kubectl failed (cert-manager CRDs installed?): ${e.message}`);
        }

        const certs = JSON.parse(certOutput);
        const expiring: Array<{
          namespace: string;
          name: string;
          secretName: string;
          dnsNames: string[];
          notAfter: string;
          daysRemaining: number;
          issuer: string;
          ready: boolean;
        }> = [];

        for (const cert of certs.items) {
          const notAfter = cert.status?.notAfter;
          if (!notAfter) continue;

          const expiryDate = new Date(notAfter);
          const daysRemaining = Math.floor((expiryDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

          if (expiryDate <= threshold) {
            const readyCondition = cert.status?.conditions?.find((c: any) => c.type === 'Ready');
            expiring.push({
              namespace: cert.metadata.namespace,
              name: cert.metadata.name,
              secretName: cert.spec.secretName,
              dnsNames: cert.spec.dnsNames || [],
              notAfter,
              daysRemaining,
              issuer: cert.spec.issuerRef?.name || 'unknown',
              ready: readyCondition?.status === 'True',
            });
          }
        }

        // Sort by most urgent first
        expiring.sort((a, b) => a.daysRemaining - b.daysRemaining);

        this.state.addAuditEntry({
          action: 'cert_check',
          result: 'success',
          details: { expiringCerts: expiring.length, thresholdDays: expiryDays },
        });

        // Notify Slack if configured
        if (expiring.length > 0) {
          const slackConfig = this.state.getCache('slack_config');
          if (slackConfig?.webhook_url && slackConfig?.notify_on?.cert_expiring) {
            const certList = expiring.slice(0, 5).map((c) =>
              `• \`${c.namespace}/${c.name}\` — ${c.daysRemaining}d remaining (${c.dnsNames.join(', ')})`
            ).join('\n');
            await this.sendSlackNotification(slackConfig.webhook_url, {
              text: `🔒 ${expiring.length} certificate(s) expiring within ${expiryDays} days:\n${certList}`,
            });
          }
        }

        return { expiring, total: expiring.length, thresholdDays: expiryDays };
      }

      case 'cert_renew': {
        const method = args.method || 'force_renewal';

        if (method === 'force_renewal') {
          // Get the Certificate to find the secret name
          let certJson: string;
          try {
            certJson = execFileSync('kubectl', [
              'get', 'certificate', args.certificate_name,
              '-n', args.namespace, '-o', 'json',
            ], { encoding: 'utf8', timeout: 15_000 });
          } catch (e: any) {
            throw new Error(`Certificate ${args.certificate_name} not found in ${args.namespace}: ${e.message}`);
          }

          const cert = JSON.parse(certJson);
          const secretName = cert.spec.secretName;

          // Use cmctl renew if available, otherwise delete the secret
          try {
            execFileSync('cmctl', ['renew', args.certificate_name, '-n', args.namespace], {
              encoding: 'utf8', timeout: 15_000,
            });
          } catch {
            // Fallback: delete the secret to trigger re-issuance
            execFileSync('kubectl', [
              'delete', 'secret', secretName, '-n', args.namespace,
            ], { encoding: 'utf8', timeout: 15_000 });
          }

          this.state.addAuditEntry({
            action: 'cert_renew',
            result: 'renewed',
            details: { certificate: args.certificate_name, namespace: args.namespace, method: 'force_renewal', secretName },
          });

          return {
            success: true,
            method: 'force_renewal',
            certificate: args.certificate_name,
            namespace: args.namespace,
            secretDeleted: secretName,
            message: 'Certificate renewal triggered. cert-manager will re-issue.',
          };
        }

        if (method === 'gitops_pr') {
          if (!args.gitops_owner || !args.gitops_repo || !args.manifest_path) {
            throw new Error('gitops_owner, gitops_repo, and manifest_path are required for gitops_pr method');
          }

          const file = await this.github.getFileContent(args.gitops_owner, args.gitops_repo, args.manifest_path);
          let content = file.content;

          // Bump a renewal annotation to trigger re-sync
          const renewalTs = new Date().toISOString();
          if (content.includes('git-steer/renew-at')) {
            content = content.replace(/git-steer\/renew-at:\s*["']?[^"'\n]+["']?/, `git-steer/renew-at: "${renewalTs}"`);
          } else {
            // Add annotation after metadata.annotations
            content = content.replace(
              /(annotations:\s*\n)/,
              `$1    git-steer/renew-at: "${renewalTs}"\n`
            );
          }

          const branchName = `cert-renew/${args.namespace}-${args.certificate_name}-${Date.now()}`;

          await this.github.commitFiles(args.gitops_owner, args.gitops_repo, {
            branch: branchName,
            message: `fix(cert): trigger renewal for ${args.certificate_name}`,
            files: [{ path: args.manifest_path, content }],
            createBranch: true,
            baseBranch: 'main',
          });

          const prefix = `[Cert Renewal] ${args.namespace}/${args.certificate_name}`;
          const openPrs = await this.github.listPullRequests(args.gitops_owner, args.gitops_repo, { state: 'open' });
          const existingPr = openPrs.find((pr) => pr.title.startsWith(prefix));

          if (existingPr) {
            return { created: false, dedup_hit: true, existing_pr: existingPr };
          }

          const pr = await this.github.createPullRequest(args.gitops_owner, args.gitops_repo, {
            title: `${prefix} — trigger re-issuance`,
            body: `## Certificate Renewal\n\n**Certificate:** \`${args.namespace}/${args.certificate_name}\`\n**Method:** GitOps PR with renewal annotation\n\n_Auto-generated by git-steer cert_renew_`,
            head: branchName,
            base: 'main',
            labels: ['certificate', 'auto-remediation'],
          });

          this.state.addAuditEntry({
            action: 'cert_renew',
            result: 'pr_created',
            details: { certificate: args.certificate_name, namespace: args.namespace, method: 'gitops_pr', prNumber: pr.number },
          });

          return {
            success: true,
            method: 'gitops_pr',
            pr: { number: pr.number, url: pr.url },
          };
        }

        throw new Error(`Unknown method: ${method}`);
      }

      // ===== Slack Integration =====
      case 'slack_notify': {
        const webhookUrl = args.webhook_url || this.state.getCache('slack_config')?.webhook_url;
        if (!webhookUrl) {
          throw new Error('No Slack webhook URL configured. Use slack_configure first or pass webhook_url.');
        }

        const payload: Record<string, any> = { text: args.message };
        if (args.blocks) payload.blocks = args.blocks;

        await this.sendSlackNotification(webhookUrl, payload);

        this.state.addAuditEntry({
          action: 'slack_notify',
          result: 'sent',
          details: { channel: args.channel || 'default' },
        });

        return { success: true, message: 'Notification sent' };
      }

      case 'slack_configure': {
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

        this.state.setCache('slack_config', config);

        this.state.addAuditEntry({
          action: 'slack_configure',
          result: 'configured',
          details: { channel: config.default_channel, events: Object.keys(config.notify_on).filter((k) => (config.notify_on as any)[k]) },
        });

        return { success: true, config };
      }

      // ===== Operational Metrics =====
      case 'ops_metrics': {
        const period = args.period || '7d';
        const now = new Date();
        let since: Date;

        switch (period) {
          case '24h': since = new Date(now.getTime() - 24 * 60 * 60 * 1000); break;
          case '7d': since = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); break;
          case '30d': since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); break;
          default: since = new Date(0); break;
        }

        const sinceIso = since.toISOString();
        const audit = this.state.getRecentAudit(10000).filter((e) => e.ts >= sinceIso);

        // Alert frequency
        const alertEntries = audit.filter((e) => e.action === 'pr_dedup_create' || e.action === 'pr_dedup_check');
        const alertsPerDay = alertEntries.length / Math.max(1, (now.getTime() - since.getTime()) / (24 * 60 * 60 * 1000));

        // Dedup hit rate
        const dedupChecks = audit.filter((e) => e.action === 'pr_dedup_create');
        const dedupHits = dedupChecks.filter((e) => e.result === 'dedup_hit');
        const dedupHitRate = dedupChecks.length > 0 ? dedupHits.length / dedupChecks.length : 0;

        // Auto-merge success (look for fabric_git_merge_pull_request entries)
        const mergeAttempts = audit.filter((e) => e.action === 'fabric_git_merge_pull_request');
        const mergeSuccesses = mergeAttempts.filter((e) => e.result === 'success');
        const mergeSuccessRate = mergeAttempts.length > 0 ? mergeSuccesses.length / mergeAttempts.length : 0;

        // Mean time to remediation (from oomkill_detect to oomkill_remediate)
        const remediations = audit.filter((e) => e.action === 'oomkill_remediate' && e.result === 'pr_created');
        const detections = audit.filter((e) => e.action === 'oomkill_detect');

        // OOMKill events
        const oomEvents = audit.filter((e) => e.action === 'oomkill_detect');
        const oomTotal = oomEvents.reduce((sum, e) => sum + (e.details?.oomPodsFound || 0), 0);

        // Cert events
        const certChecks = audit.filter((e) => e.action === 'cert_check');
        const certRenewals = audit.filter((e) => e.action === 'cert_renew');

        // Security metrics from existing system
        const securityMetrics = this.state.getMetrics({
          start: sinceIso,
          end: now.toISOString(),
        });

        return {
          period,
          alerts: {
            total: alertEntries.length,
            perDay: Math.round(alertsPerDay * 10) / 10,
          },
          dedup: {
            checks: dedupChecks.length,
            hits: dedupHits.length,
            hitRate: Math.round(dedupHitRate * 100) + '%',
          },
          autoMerge: {
            attempts: mergeAttempts.length,
            successes: mergeSuccesses.length,
            successRate: Math.round(mergeSuccessRate * 100) + '%',
          },
          oomkill: {
            detections: oomEvents.length,
            totalPods: oomTotal,
            remediations: remediations.length,
          },
          certificates: {
            checks: certChecks.length,
            renewals: certRenewals.length,
          },
          security: {
            totalCves: securityMetrics.totalCves,
            fixedCves: securityMetrics.fixedCves,
            fixRate: Math.round(securityMetrics.fixRate * 100) + '%',
            avgMttrHours: Math.round(securityMetrics.avgMttr),
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

      // ========== Fabric Tools (routed via gateway) ==========

      case 'fabric_cve_scan':
      case 'fabric_cve_enrich':
      case 'fabric_cve_triage':
      case 'fabric_cve_queue':
      case 'fabric_cve_stats':
      case 'fabric_cve_compact': {
        if (!this.gateway?.available) {
          throw new Error('Fabric CVE app not available.');
        }

        const TOOL_MAP: Record<string, string> = {
          'fabric_cve_scan': 'cve_scan',
          'fabric_cve_enrich': 'cve_enrich',
          'fabric_cve_triage': 'cve_triage',
          'fabric_cve_queue': 'cve_queue_list',
          'fabric_cve_stats': 'cve_queue_stats',
          'fabric_cve_compact': 'cve_compact',
        };

        const routeArgs = { ...args };
        if (name === 'fabric_cve_scan' && !routeArgs.repos) {
          routeArgs.repos = this.state.getManagedRepos()
            .filter((r: any) => r.name !== '*')
            .map((r: any) => `${r.owner}/${r.name}`);
        }

        const result = await this.gateway.router.route(TOOL_MAP[name], routeArgs);

        this.state.addAuditEntry({
          action: name,
          result: 'success',
          details: { routed_to: `${result.app}/${result.tool}`, duration_ms: result.durationMs, ...args },
        });

        // Gateway tool execute() returns JSON strings — parse for MCP response
        return typeof result.result === 'string' ? JSON.parse(result.result) : result.result;
      }

      // ========== Fabric Git Tools (routed via @git-fabric/git) ==========
      case 'fabric_git_list_repos':
      case 'fabric_git_get_file':
      case 'fabric_git_list_files':
      case 'fabric_git_commit_files':
      case 'fabric_git_list_commits':
      case 'fabric_git_get_commit':
      case 'fabric_git_compare_commits':
      case 'fabric_git_list_branches':
      case 'fabric_git_create_branch':
      case 'fabric_git_delete_branch':
      case 'fabric_git_list_pull_requests':
      case 'fabric_git_get_pull_request':
      case 'fabric_git_create_pull_request':
      case 'fabric_git_merge_pull_request': {
        if (!this.gateway?.available) {
          throw new Error('Fabric git app not available.');
        }

        const GIT_TOOL_MAP: Record<string, string> = {
          'fabric_git_list_repos':        'git_repo_list',
          'fabric_git_get_file':          'git_file_get',
          'fabric_git_list_files':        'git_file_list',
          'fabric_git_commit_files':      'git_commit_push',
          'fabric_git_list_commits':      'git_commit_list',
          'fabric_git_get_commit':        'git_commit_get',
          'fabric_git_compare_commits':   'git_commit_compare',
          'fabric_git_list_branches':     'git_branch_list',
          'fabric_git_create_branch':     'git_branch_create',
          'fabric_git_delete_branch':     'git_branch_delete',
          'fabric_git_list_pull_requests':'git_pr_list',
          'fabric_git_get_pull_request':  'git_pr_get',
          'fabric_git_create_pull_request':'git_pr_create',
          'fabric_git_merge_pull_request':'git_pr_merge',
        };

        const gitResult = await this.gateway.router.route(GIT_TOOL_MAP[name], args);

        this.state.addAuditEntry({
          action: name,
          result: 'success',
          details: { routed_to: `${gitResult.app}/${gitResult.tool}`, duration_ms: gitResult.durationMs, ...args },
        });

        return typeof gitResult.result === 'string' ? JSON.parse(gitResult.result) : gitResult.result;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async sendSlackNotification(webhookUrl: string, payload: Record<string, any>): Promise<void> {
    try {
      const res = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        console.warn(`[git-steer] Slack notification failed: ${res.status} ${res.statusText}`);
      }
    } catch (e: any) {
      console.warn(`[git-steer] Slack notification error: ${e.message}`);
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

    // Initialize fabric gateway if not provided via config
    if (!this.gateway) {
      this.gateway = await initGateway({
        githubToken: process.env.GITHUB_TOKEN ?? process.env.GIT_STEER_TOKEN ?? '',
        stateRepo: this.state.getStateRepo(),
        managedRepos: this.state.getManagedRepos()
          .filter((r: any) => r.name !== '*')
          .map((r: any) => `${r.owner}/${r.name}`),
      });
    }

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
