/**
 * State Manager
 * 
 * Manages all git-steer state persisted to the state repo on GitHub.
 * State is loaded at startup and saved on shutdown or explicit sync.
 */

import { GitHubClient } from '../github/client.js';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export interface StateManagerConfig {
  github: GitHubClient;
  repo: string;
}

export interface ManagedRepo {
  owner: string;
  name: string;
  policies: string[];
}

export interface Policy {
  branches?: string[];
  protection?: {
    required_reviews?: number;
    dismiss_stale_reviews?: boolean;
    require_code_owner_reviews?: boolean;
  };
  auto_merge?: {
    type: string;
    update_type: string[];
    merge_method: string;
  };
}

export interface Schedule {
  cron: string;
  action: string;
  params: Record<string, any>;
}

export interface AuditEntry {
  ts: string;
  action: string;
  repo?: string;
  branch?: string;
  result: string;
  details?: Record<string, any>;
}

export interface StateData {
  config: {
    managedRepos: ManagedRepo[];
    policies: Record<string, Policy>;
    schedules: Record<string, Schedule>;
  };
  state: {
    audit: AuditEntry[];
    jobs: any[];
    cache: Record<string, any>;
  };
  shas: Record<string, string>;
}

export class StateManager {
  private github: GitHubClient;
  private repo: string;
  private owner: string | null = null;
  private data: StateData | null = null;
  private dirty = false;
  private lastSync: Date | null = null;

  constructor(config: StateManagerConfig) {
    this.github = config.github;
    this.repo = config.repo;
  }

  /**
   * Load all state from GitHub
   */
  async load(): Promise<void> {
    // Get owner from authenticated user
    const repos = await this.github.listRepos();
    const stateRepo = repos.find((r) => r.name === this.repo);
    
    if (!stateRepo) {
      throw new Error(`State repo ${this.repo} not found. Run 'git-steer init' first.`);
    }

    this.owner = stateRepo.owner;

    // Load config files
    const managedRepos = await this.loadYaml('config/managed-repos.yaml');
    const policies = await this.loadYaml('config/policies.yaml');
    const schedules = await this.loadYaml('config/schedules.yaml');

    // Load state files
    const audit = await this.loadJsonLines('state/audit.jsonl');
    const jobs = await this.loadJsonLines('state/jobs.jsonl');
    const cache = await this.loadJson('state/cache.json');

    this.data = {
      config: {
        managedRepos: managedRepos.repos || [],
        policies: policies.policies || {},
        schedules: schedules.schedules || {},
      },
      state: {
        audit,
        jobs,
        cache,
      },
      shas: {},
    };

    this.lastSync = new Date();
    this.dirty = false;
  }

  /**
   * Save all dirty state to GitHub
   */
  async save(): Promise<void> {
    if (!this.data || !this.owner) {
      throw new Error('State not loaded');
    }

    // Save audit log (append-only)
    await this.saveJsonLines('state/audit.jsonl', this.data.state.audit);

    // Save jobs
    await this.saveJsonLines('state/jobs.jsonl', this.data.state.jobs);

    // Save cache
    await this.saveJson('state/cache.json', this.data.state.cache);

    // Save config if modified
    await this.saveYaml('config/managed-repos.yaml', {
      repos: this.data.config.managedRepos,
    });
    await this.saveYaml('config/policies.yaml', {
      policies: this.data.config.policies,
    });
    await this.saveYaml('config/schedules.yaml', {
      schedules: this.data.config.schedules,
    });

    this.lastSync = new Date();
    this.dirty = false;
  }

  // ========== State Access ==========

  isDirty(): boolean {
    return this.dirty;
  }

  getLastSync(): Date | null {
    return this.lastSync;
  }

  getManagedRepos(): ManagedRepo[] {
    return this.data?.config.managedRepos || [];
  }

  getPolicies(): Record<string, Policy> {
    return this.data?.config.policies || {};
  }

  getScheduledJobs(): Array<{ name: string; schedule: Schedule }> {
    if (!this.data) return [];
    return Object.entries(this.data.config.schedules).map(([name, schedule]) => ({
      name,
      schedule,
    }));
  }

  getRecentAudit(limit: number): AuditEntry[] {
    if (!this.data) return [];
    return this.data.state.audit.slice(-limit);
  }

  // ========== State Mutations ==========

  addAuditEntry(entry: Omit<AuditEntry, 'ts'>): void {
    if (!this.data) return;

    this.data.state.audit.push({
      ...entry,
      ts: new Date().toISOString(),
    });

    // Rotate audit log to prevent unbounded memory growth (keep last 10000 entries)
    const MAX_AUDIT_ENTRIES = 10000;
    if (this.data.state.audit.length > MAX_AUDIT_ENTRIES) {
      this.data.state.audit = this.data.state.audit.slice(-MAX_AUDIT_ENTRIES);
    }

    this.dirty = true;
  }

  addManagedRepo(repo: ManagedRepo): void {
    if (!this.data) return;
    
    // Check if already managed
    const existing = this.data.config.managedRepos.find(
      (r) => r.owner === repo.owner && r.name === repo.name
    );
    
    if (!existing) {
      this.data.config.managedRepos.push(repo);
      this.dirty = true;
    }
  }

  removeManagedRepo(owner: string, name: string): void {
    if (!this.data) return;
    
    this.data.config.managedRepos = this.data.config.managedRepos.filter(
      (r) => !(r.owner === owner && r.name === name)
    );
    this.dirty = true;
  }

  updatePolicy(name: string, policy: Policy): void {
    if (!this.data) return;
    
    this.data.config.policies[name] = policy;
    this.dirty = true;
  }

  updateSchedule(name: string, schedule: Schedule): void {
    if (!this.data) return;
    
    this.data.config.schedules[name] = schedule;
    this.dirty = true;
  }

  setCache(key: string, value: any): void {
    if (!this.data) return;
    
    this.data.state.cache[key] = value;
    this.dirty = true;
  }

  getCache(key: string): any {
    return this.data?.state.cache[key];
  }

  // ========== File Helpers ==========

  private async loadYaml(path: string): Promise<any> {
    try {
      const { content, sha } = await this.github.getFileContent(
        this.owner!,
        this.repo,
        path
      );
      if (this.data) {
        this.data.shas[path] = sha;
      }
      return parseYaml(content) || {};
    } catch {
      return {};
    }
  }

  private async loadJson(path: string): Promise<any> {
    try {
      const { content, sha } = await this.github.getFileContent(
        this.owner!,
        this.repo,
        path
      );
      if (this.data) {
        this.data.shas[path] = sha;
      }
      return JSON.parse(content);
    } catch {
      return {};
    }
  }

  private async loadJsonLines(path: string): Promise<any[]> {
    try {
      const { content, sha } = await this.github.getFileContent(
        this.owner!,
        this.repo,
        path
      );
      if (this.data) {
        this.data.shas[path] = sha;
      }
      return content
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => JSON.parse(line));
    } catch {
      return [];
    }
  }

  private async saveYaml(path: string, data: any): Promise<void> {
    const content = stringifyYaml(data);
    await this.github.updateFileContent(
      this.owner!,
      this.repo,
      path,
      content,
      `Update ${path}`,
      this.data?.shas[path]
    );
  }

  private async saveJson(path: string, data: any): Promise<void> {
    const content = JSON.stringify(data, null, 2);
    await this.github.updateFileContent(
      this.owner!,
      this.repo,
      path,
      content,
      `Update ${path}`,
      this.data?.shas[path]
    );
  }

  private async saveJsonLines(path: string, data: any[]): Promise<void> {
    const content = data.map((item) => JSON.stringify(item)).join('\n');
    await this.github.updateFileContent(
      this.owner!,
      this.repo,
      path,
      content,
      `Update ${path}`,
      this.data?.shas[path]
    );
  }
}
