/**
 * State Manager
 * 
 * Manages all git-steer state persisted to the state repo on GitHub.
 * State is loaded at startup and saved on shutdown or explicit sync.
 */

import { GitHubClient } from '../github/client.js';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { etagCache } from '../core/etag-cache.js';

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
  // Rate limit telemetry (Step 6)
  rate_remaining?: number;   // core bucket remaining at time of log
  rate_reset?: string;       // ISO timestamp when core bucket resets
  is_secondary_limit_hit?: boolean;
  retry_count?: number;
  backoff_ms?: number;
}

export interface RfcVulnerability {
  cve: string | null;
  package: string;
  severity: string;
  fixVersion: string | null;
}

export interface RfcEntry {
  ts: string;
  repo: string;
  issueNumber: number;
  issueUrl: string;
  severity: string;
  vulnerabilities: RfcVulnerability[];
  status: 'open' | 'in_progress' | 'fixed' | 'closed';
  prNumber?: number;
  prUrl?: string;
  releaseId?: number;
  releaseUrl?: string;
  fixedAt?: string;
  mttr?: number; // hours
}

export interface QualityFinding {
  file: string;
  line: number;
  rule: string;
  message: string;
  severity: string;
}

export interface QualityEntry {
  ts: string;
  repo: string;
  tool: string;
  findings: number;
  errors: number;
  warnings: number;
  details?: QualityFinding[];
}

export interface SecurityMetrics {
  totalCves: number;
  fixedCves: number;
  fixRate: number;
  avgMttr: number;
  bySeverity: Record<string, { total: number; fixed: number }>;
  byRepo: Record<string, { total: number; fixed: number }>;
  timeline: Array<{ date: string; opened: number; fixed: number }>;
}

export interface SweepCursor {
  /** Full repo list the sweep was started with, in stable order. */
  repos: Array<{ owner: string; name: string; fullName: string }>;
  /** Index of the next repo to process. */
  nextIndex: number;
  /** ISO timestamp when the sweep was initiated. */
  startedAt: string;
  /** Sweep parameters carried forward for resume calls. */
  params: { severity: string; skipRfc: boolean; dryRun: boolean };
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
    rfcs: RfcEntry[];
    quality: QualityEntry[];
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
   * Get the state repo name (without owner prefix).
   */
  getRepoName(): string {
    return this.repo;
  }

  /**
   * Get owner, throwing if not loaded
   */
  private getOwner(): string {
    if (!this.owner) {
      throw new Error('State not loaded. Call load() first.');
    }
    return this.owner;
  }

  /**
   * Load all state from GitHub
   */
  async load(): Promise<void> {
    // Resolve the installation owner via GraphQL viewer query — one round-trip
    // instead of paginating GET /installation/repositories just to read owner.login.
    this.owner = await this.github.getViewerLogin();

    // Load config files
    const managedRepos = await this.loadYaml('config/managed-repos.yaml');
    const policies = await this.loadYaml('config/policies.yaml');
    const schedules = await this.loadYaml('config/schedules.yaml');

    // Load state files
    const audit = await this.loadJsonLines('state/audit.jsonl');
    const jobs = await this.loadJsonLines('state/jobs.jsonl');
    const cache = await this.loadJson('state/cache.json');
    const rfcs = await this.loadJsonLines('state/rfcs.jsonl');
    const quality = await this.loadJsonLines('state/quality.jsonl');

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
        rfcs,
        quality,
      },
      shas: {},
    };

    // Restore ETag cache from persisted state so conditional requests work
    // across process restarts, not just within a single session.
    if (cache._etags && typeof cache._etags === 'object') {
      etagCache.load(cache._etags);
    }

    this.lastSync = new Date();
    this.dirty = false;
  }

  /**
   * Save all dirty state to GitHub.
   *
   * **Consistency model:**
   *
   * 1. Files are written sequentially via the GitHub Contents API, not
   *    atomically. There is no transaction boundary across files.
   *
   * 2. If the process crashes mid-save, state becomes inconsistent.
   *    For example, `state/audit.jsonl` may be updated while
   *    `state/rfcs.jsonl` still contains stale data.
   *
   * 3. Each file write uses SHA-based conflict detection (the `sha`
   *    parameter in the Contents API). This prevents overwriting
   *    concurrent changes to the *same* file, but does not prevent
   *    logical conflicts *across* files (e.g., an RFC referencing an
   *    audit entry that was never persisted).
   *
   * 4. Two concurrent sessions (e.g., the MCP server and the heartbeat
   *    GitHub Actions workflow) may both call `save()`. Because conflict
   *    detection is per-file, each session's writes succeed independently
   *    -- last-write-wins on a per-file basis. No cross-file ordering
   *    guarantee exists between sessions.
   */
  async save(): Promise<void> {
    if (!this.data || !this.owner) {
      throw new Error('State not loaded');
    }

    // Save audit log (append-only)
    await this.saveJsonLines('state/audit.jsonl', this.data.state.audit);

    // Save jobs
    await this.saveJsonLines('state/jobs.jsonl', this.data.state.jobs);

    // Save RFCs
    await this.saveJsonLines('state/rfcs.jsonl', this.data.state.rfcs);

    // Save quality results
    await this.saveJsonLines('state/quality.jsonl', this.data.state.quality);

    // Persist ETag map so conditional requests survive process restarts.
    this.data.state.cache._etags = etagCache.snapshot();

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

  getStateRepo(): string {
    return this.owner ? `${this.owner}/${this.repo}` : this.repo;
  }

  /**
   * Get the resolved owner (GitHub login). Throws if state not loaded.
   */
  getOwnerName(): string {
    return this.getOwner();
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

  // ========== Sweep Cursor ==========

  getSweepCursor(): SweepCursor | null {
    return this.data?.state.cache['_sweepCursor'] ?? null;
  }

  setSweepCursor(cursor: SweepCursor): void {
    if (!this.data) return;
    this.data.state.cache['_sweepCursor'] = cursor;
    this.dirty = true;
  }

  clearSweepCursor(): void {
    if (!this.data) return;
    delete this.data.state.cache['_sweepCursor'];
    this.dirty = true;
  }

  /** Record when a repo was last successfully swept (ISO string). */
  setLastSweptAt(fullName: string, ts: string): void {
    if (!this.data) return;
    const map: Record<string, string> = this.data.state.cache['_lastSwept'] ?? {};
    map[fullName] = ts;
    this.data.state.cache['_lastSwept'] = map;
    this.dirty = true;
  }

  /** Return ISO timestamp of last successful sweep for a repo, or null. */
  getLastSweptAt(fullName: string): string | null {
    return this.data?.state.cache['_lastSwept']?.[fullName] ?? null;
  }

  // ========== RFC Operations ==========

  getRfcs(filter?: { repo?: string; status?: RfcEntry['status'] }): RfcEntry[] {
    if (!this.data) return [];
    let rfcs = this.data.state.rfcs;
    if (filter?.repo) {
      rfcs = rfcs.filter((r) => r.repo === filter.repo);
    }
    if (filter?.status) {
      rfcs = rfcs.filter((r) => r.status === filter.status);
    }
    return rfcs;
  }

  addRfc(rfc: Omit<RfcEntry, 'ts'>): void {
    if (!this.data) return;
    this.data.state.rfcs.push({
      ...rfc,
      ts: new Date().toISOString(),
    });
    this.dirty = true;
  }

  updateRfc(
    repo: string,
    issueNumber: number,
    updates: Partial<Pick<RfcEntry, 'status' | 'prNumber' | 'prUrl' | 'releaseId' | 'releaseUrl' | 'fixedAt' | 'mttr'>>
  ): void {
    if (!this.data) return;
    const rfc = this.data.state.rfcs.find(
      (r) => r.repo === repo && r.issueNumber === issueNumber
    );
    if (rfc) {
      Object.assign(rfc, updates);
      this.dirty = true;
    }
  }

  // ========== Quality Operations ==========

  getQualityResults(filter?: { repo?: string; tool?: string }): QualityEntry[] {
    if (!this.data) return [];
    let results = this.data.state.quality;
    if (filter?.repo) {
      results = results.filter((q) => q.repo === filter.repo);
    }
    if (filter?.tool) {
      results = results.filter((q) => q.tool === filter.tool);
    }
    return results;
  }

  addQualityResult(result: Omit<QualityEntry, 'ts'>): void {
    if (!this.data) return;
    this.data.state.quality.push({
      ...result,
      ts: new Date().toISOString(),
    });
    this.dirty = true;
  }

  // ========== Metrics ==========

  getMetrics(dateRange?: { start: string; end: string }): SecurityMetrics {
    const rfcs = this.data?.state.rfcs || [];

    let filtered = rfcs;
    if (dateRange) {
      filtered = rfcs.filter((r) => r.ts >= dateRange.start && r.ts <= dateRange.end);
    }

    const totalCves = filtered.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    const fixedRfcs = filtered.filter((r) => r.status === 'fixed');
    const fixedCves = fixedRfcs.reduce((sum, r) => sum + r.vulnerabilities.length, 0);

    // MTTR calculation
    const mttrs = fixedRfcs.filter((r) => r.mttr != null).map((r) => r.mttr!);
    const avgMttr = mttrs.length > 0 ? mttrs.reduce((a, b) => a + b, 0) / mttrs.length : 0;

    // By severity
    const bySeverity: Record<string, { total: number; fixed: number }> = {};
    for (const rfc of filtered) {
      const sev = rfc.severity;
      if (!bySeverity[sev]) bySeverity[sev] = { total: 0, fixed: 0 };
      bySeverity[sev].total += rfc.vulnerabilities.length;
      if (rfc.status === 'fixed') {
        bySeverity[sev].fixed += rfc.vulnerabilities.length;
      }
    }

    // By repo
    const byRepo: Record<string, { total: number; fixed: number }> = {};
    for (const rfc of filtered) {
      if (!byRepo[rfc.repo]) byRepo[rfc.repo] = { total: 0, fixed: 0 };
      byRepo[rfc.repo].total += rfc.vulnerabilities.length;
      if (rfc.status === 'fixed') {
        byRepo[rfc.repo].fixed += rfc.vulnerabilities.length;
      }
    }

    // Timeline (group by date)
    const timelineMap = new Map<string, { opened: number; fixed: number }>();
    for (const rfc of filtered) {
      const date = rfc.ts.split('T')[0];
      if (!timelineMap.has(date)) timelineMap.set(date, { opened: 0, fixed: 0 });
      timelineMap.get(date)!.opened += rfc.vulnerabilities.length;
    }
    for (const rfc of fixedRfcs) {
      if (rfc.fixedAt) {
        const date = rfc.fixedAt.split('T')[0];
        if (!timelineMap.has(date)) timelineMap.set(date, { opened: 0, fixed: 0 });
        timelineMap.get(date)!.fixed += rfc.vulnerabilities.length;
      }
    }
    const timeline = Array.from(timelineMap.entries())
      .map(([date, counts]) => ({ date, ...counts }))
      .sort((a, b) => a.date.localeCompare(b.date));

    return {
      totalCves,
      fixedCves,
      fixRate: totalCves > 0 ? fixedCves / totalCves : 0,
      avgMttr,
      bySeverity,
      byRepo,
      timeline,
    };
  }

  // ========== File Helpers ==========

  private async loadYaml(path: string): Promise<any> {
    try {
      const { content, sha } = await this.github.getFileContent(
        this.getOwner(),
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
        this.getOwner(),
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
        this.getOwner(),
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
      this.getOwner(),
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
      this.getOwner(),
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
      this.getOwner(),
      this.repo,
      path,
      content,
      `Update ${path}`,
      this.data?.shas[path]
    );
  }
}
