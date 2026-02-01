/**
 * MCP Server for git-steer
 * 
 * Exposes all git-steer capabilities as MCP tools.
 * Supports stdio and HTTP/SSE transports.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { GitHubClient } from '../github/client.js';
import { StateManager } from '../state/manager.js';
import { createRequire } from 'module';

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
];

export class MCPServer {
  private server: Server;
  private github: GitHubClient;
  private state: StateManager;
  private config: MCPServerConfig;

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
        
        // Log to audit
        this.state.addAuditEntry({
          action: name,
          repo: args?.repo ? `${args.owner}/${args.repo}` : undefined,
          result: 'success',
          details: args,
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
        // Log error to audit
        this.state.addAuditEntry({
          action: name,
          repo: args?.repo ? `${args.owner}/${args.repo}` : undefined,
          result: 'error',
          details: { error: error.message },
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
        const branches = await this.github.listBranches(args.owner, args.repo);
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
        const branches = await this.github.listBranches(args.owner, args.repo);
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

        for (const repo of managedRepos) {
          if (repo.name === '*') continue; // Skip wildcard entries for now
          
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
        }

        return digest;
      }

      // State tools
      case 'steer_status': {
        const rateLimit = await this.github.getRateLimit();
        return {
          github: {
            authenticated: this.github.isAuthenticated(),
            rateLimit: {
              remaining: rateLimit.remaining,
              limit: rateLimit.limit,
              resetsAt: rateLimit.reset.toISOString(),
            },
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
        return { added: true, repo: `${args.owner}/${args.name}` };
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

        for (const repo of repos) {
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
        }

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

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  async start(): Promise<void> {
    if (this.config.transport === 'stdio') {
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
    } else {
      // HTTP/SSE transport would go here
      throw new Error('HTTP transport not yet implemented');
    }
  }

  async stop(): Promise<void> {
    await this.server.close();
  }
}
