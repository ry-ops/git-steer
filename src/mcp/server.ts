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
