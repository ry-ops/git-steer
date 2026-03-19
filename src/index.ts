/**
 * git-steer core engine
 * 
 * Coordinates between GitHub API, state management, and MCP server.
 * Runs entirely in-memory with state persisted to GitHub.
 */

import { KeychainService } from './core/keychain.js';
import { StateManager } from './state/manager.js';
import { MCPServer } from './mcp/server.js';
import { GitHubClient } from './github/client.js';
import { initGateway } from './fabric/gateway.js';
import type { GatewayHandle } from './fabric/gateway.js';
import { generateDashboardHtml } from './dashboard/templates.js';

export interface GitSteerConfig {
  keychain: KeychainService;
  stateRepo?: string;
}

export interface ServerOptions {
  transport: 'stdio' | 'http';
  port?: number;
}

export class GitSteer {
  private keychain: KeychainService;
  private github: GitHubClient | null = null;
  private state: StateManager | null = null;
  private mcp: MCPServer | null = null;
  private gateway: GatewayHandle | null = null;
  private stateRepo: string;

  constructor(config: GitSteerConfig) {
    this.keychain = config.keychain;
    this.stateRepo = config.stateRepo || 'git-steer-state';
  }

  /**
   * Initialize GitHub client from Keychain credentials
   */
  async initGitHub(): Promise<void> {
    const appId = await this.keychain.get('git-steer-app-id');
    const privateKey = await this.keychain.get('git-steer-private-key');
    const installationId = await this.keychain.get('git-steer-installation-id');

    if (!appId || !privateKey || !installationId) {
      throw new Error('Missing GitHub App credentials in Keychain');
    }

    this.github = new GitHubClient({
      appId,
      privateKey,
      installationId,
    });

    await this.github.authenticate();
  }

  /**
   * Pull current state from the state repo on GitHub
   */
  async syncState(): Promise<void> {
    if (!this.github) {
      await this.initGitHub();
    }

    if (!this.github) {
      throw new Error('Failed to initialize GitHub client');
    }

    this.state = new StateManager({
      github: this.github,
      repo: this.stateRepo,
    });

    await this.state.load();
  }

  /**
   * Force push current state to GitHub
   */
  async forceSyncState(): Promise<void> {
    if (!this.state) {
      throw new Error('State not loaded');
    }
    await this.state.save();
  }

  /**
   * Initialize the fabric gateway for CVE scanning.
   * Prefers GITHUB_TOKEN / GIT_STEER_TOKEN env vars (MCP server path),
   * falls back to generating an installation token from App credentials (CLI path).
   */
  async initFabricGateway(): Promise<GatewayHandle> {
    if (!this.github || !this.state) {
      throw new Error('Not initialized. Call syncState() first.');
    }

    const token = process.env.GITHUB_TOKEN
      ?? process.env.GIT_STEER_TOKEN
      ?? await this.github.getInstallationToken();

    const managedRepos = this.state.getManagedRepos()
      .filter((r: any) => r.name !== '*')
      .map((r: any) => `${r.owner}/${r.name}`);

    this.gateway = await initGateway({
      githubToken: token,
      stateRepo: this.state.getStateRepo(),
      managedRepos,
    });

    return this.gateway;
  }

  /**
   * Expose state manager for CLI commands
   */
  _getState(): StateManager {
    if (!this.state) throw new Error('Not initialized. Call syncState() first.');
    return this.state;
  }

  /**
   * Expose gateway for CLI commands
   */
  _getGateway(): GatewayHandle {
    if (!this.gateway) throw new Error('Gateway not initialized. Call initFabricGateway() first.');
    return this.gateway;
  }

  /**
   * Generate and deploy the dashboard to GitHub Pages.
   */
  async refreshDashboard(): Promise<{ dashboardUrl: string; commitSha: string }> {
    if (!this.github || !this.state) {
      throw new Error('Not initialized. Call syncState() first.');
    }

    const metrics = this.state.getMetrics();
    const rfcs = this.state.getRfcs();
    const quality = this.state.getQualityResults();
    const html = generateDashboardHtml({ metrics, rfcs, quality });

    const owner = this.state.getOwnerName();
    const stateRepo = this.state.getRepoName();

    const commitResult = await this.github.commitFiles(owner, stateRepo, {
      branch: 'gh-pages',
      message: `Update dashboard ${new Date().toISOString()}`,
      files: [{ path: 'index.html', content: html }],
      createBranch: true,
      baseBranch: 'main',
    });

    return {
      dashboardUrl: `https://${owner}.github.io/${stateRepo}/`,
      commitSha: commitResult.sha,
    };
  }

  /**
   * Start the MCP server
   */
  async startServer(options: ServerOptions): Promise<void> {
    if (!this.github || !this.state) {
      throw new Error('Not initialized. Call syncState() first.');
    }

    // Initialize gateway before constructing MCPServer so it can be shared
    if (!this.gateway) {
      await this.initFabricGateway();
    }

    this.mcp = new MCPServer({
      github: this.github,
      state: this.state,
      transport: options.transport,
      port: options.port,
      gateway: this.gateway ?? undefined,
    });

    // Save state on shutdown
    process.on('SIGINT', async () => {
      await this.shutdown();
    });

    process.on('SIGTERM', async () => {
      await this.shutdown();
    });

    await this.mcp.start();
  }

  /**
   * Graceful shutdown - persist state before exit
   */
  async shutdown(): Promise<void> {
    process.stderr.write('\n[git-steer] Shutting down...\n');
    
    if (this.state?.isDirty()) {
      process.stderr.write('[git-steer] Saving state to GitHub...\n');
      await this.state.save();
    }

    if (this.mcp) {
      await this.mcp.stop();
    }

    process.exit(0);
  }

  /**
   * Expose GitHub client for CLI commands
   */
  _getGitHub(): GitHubClient {
    if (!this.github) throw new Error('Not initialized. Call syncState() first.');
    return this.github;
  }

  /**
   * Display current status
   */
  async showStatus(): Promise<void> {
    await this.initGitHub();
    await this.syncState();

    const status = {
      github: {
        authenticated: this.github?.isAuthenticated() || false,
        rateLimit: this.github?.isAuthenticated() ? await this.github.getRateLimit() : null,
      },
      state: {
        repo: this.stateRepo,
        lastSync: this.state?.getLastSync(),
        pendingChanges: this.state?.isDirty() || false,
      },
      jobs: {
        scheduled: this.state?.getScheduledJobs() || [],
        recent: this.state?.getRecentAudit(5) || [],
      },
    };

    console.log(JSON.stringify(status, null, 2));
  }
}
