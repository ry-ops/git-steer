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
   * Start the MCP server
   */
  async startServer(options: ServerOptions): Promise<void> {
    if (!this.github || !this.state) {
      throw new Error('Not initialized. Call syncState() first.');
    }

    this.mcp = new MCPServer({
      github: this.github,
      state: this.state,
      transport: options.transport,
      port: options.port,
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
    console.log('\nShutting down...');
    
    if (this.state?.isDirty()) {
      console.log('Saving state to GitHub...');
      await this.state.save();
    }

    if (this.mcp) {
      await this.mcp.stop();
    }

    process.exit(0);
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
        rateLimit: await this.github?.getRateLimit(),
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
