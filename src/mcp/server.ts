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
import { DESTRUCTIVE_TOOLS, DRY_RUN_DEFAULT_TOOLS } from './permissions.js';
import { repos, branches, prs, security, actions, ops, k8s, misc } from './tools/index.js';
import type { ToolDeps } from './tools/types.js';
import { GitHubClient, RateLimitSnapshot } from '../github/client.js';
import { StateManager } from '../state/manager.js';
import { readLimit, writeLimit } from '../core/concurrency.js';
import { initGateway } from '../fabric/gateway.js';
import type { GatewayHandle } from '../fabric/gateway.js';
import { generateDashboardHtml } from '../dashboard/templates.js';
import { createRequire } from 'module';
import { execFileSync } from 'child_process';
import { randomUUID } from 'crypto';
import type { IncomingMessage, ServerResponse } from 'http';

const require = createRequire(import.meta.url);
const { version: VERSION } = require('../../package.json');

function binaryAvailable(name: string): boolean {
  try {
    execFileSync('which', [name], { timeout: 5000, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const HAS_KUBECTL = binaryAvailable('kubectl');
const HAS_CR = binaryAvailable('cr');

const KUBECTL_TOOLS = new Set(['oomkill_detect', 'oomkill_remediate', 'cert_check', 'cert_renew']);
const CR_TOOLS = new Set(['code_review']);

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
  // fabric_cve_triage RETIRED (ADR-007): CVE remediation now flows exclusively
  // through the single gated security-fix-worker. The Fabric path opened PRs
  // without the ADR-005 functional-integrity gate. Discovery tools below
  // (scan/enrich/queue/stats/compact) remain — they feed the dashboard.
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

// All domain modules providing tool definitions and handlers
const TOOL_MODULES = [repos, branches, prs, security, actions, ops, k8s, misc] as const;

// Collect CORE_TOOLS from all domain modules
const CORE_TOOLS: Tool[] = TOOL_MODULES.flatMap((m) => m.getTools());

// ========== Fabric Tools (via @git-fabric/git) ==========
const FABRIC_GIT_TOOLS: Tool[] = [
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
    // List available tools — fabric tools only when gateway is loaded;
    // binary-dependent tools only when the required binary is on PATH.
    const availableCoreTools = CORE_TOOLS.filter((t) => {
      if (KUBECTL_TOOLS.has(t.name) && !HAS_KUBECTL) return false;
      if (CR_TOOLS.has(t.name) && !HAS_CR) return false;
      return true;
    });

    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.gateway?.available
        ? [...availableCoreTools, ...FABRIC_CVE_TOOLS, ...FABRIC_GIT_TOOLS]
        : [...availableCoreTools, ...FABRIC_GIT_TOOLS],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Destructive tool guard (SEC-010)
      if (DESTRUCTIVE_TOOLS.has(name)) {
        const confirmValue = (args as Record<string, unknown>).confirm as string | undefined;
        const expectedConfirm = `CONFIRM_${name.toUpperCase()}`;
        if (confirmValue !== expectedConfirm) {
          return {
            content: [{
              type: 'text' as const,
              text: `${name} is a destructive operation. Pass confirm: "${expectedConfirm}" to proceed. This action cannot be undone.`,
            }],
          };
        }
      }

      // Dry-run default (SEC-010)
      if (DRY_RUN_DEFAULT_TOOLS.has(name) && (args as Record<string, unknown>).dry_run === undefined) {
        (args as Record<string, unknown>).dry_run = true;
      }

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

  /** Build the shared ToolDeps bag for domain module dispatch. */
  private buildToolDeps(): ToolDeps {
    return {
      github: this.github,
      state: this.state,
      gateway: this.gateway,
      rateLimitCache: this.rateLimitCache,
      refreshRateLimit: () => this.refreshRateLimit(),
      sendSlackNotification: (url, payload) => this.sendSlackNotification(url, payload),
      readLimit,
      writeLimit,
    };
  }

  private async executeTool(name: string, args: Record<string, any>): Promise<any> {
    // Try each domain module — first non-null result wins
    const deps = this.buildToolDeps();
    for (const mod of TOOL_MODULES) {
      const result = mod.handleCall(name, args, deps);
      if (result !== null) return result;
    }

    // Fabric tools stay in server.ts (routed via gateway)
    switch (name) {
      // ========== Fabric CVE Tools (routed via gateway) ==========
      case 'fabric_cve_scan':
      case 'fabric_cve_enrich':
      case 'fabric_cve_queue':
      case 'fabric_cve_stats':
      case 'fabric_cve_compact': {
        if (!this.gateway?.available) {
          throw new Error('Fabric CVE app not available.');
        }

        const TOOL_MAP: Record<string, string> = {
          'fabric_cve_scan': 'cve_scan',
          'fabric_cve_enrich': 'cve_enrich',
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
