/**
 * CVE scanning routes with scan lifecycle tracking
 *
 * POST /api/cve/scan                    — trigger CVE scan for a repo
 * GET  /api/cve/results/:owner/:repo    — get scan results
 * POST /api/cve/verify                  — verify fixes (body-based)
 * POST /api/cve/verify/:owner/:repo     — re-scan after fixes, compare to previous
 * GET  /api/cve/queue                   — get pending CVE queue
 * GET  /api/scans/recent                — recent scans across all repos
 * GET  /api/scans/:scanId               — single scan details
 * GET  /api/trends/:owner/:repo         — severity trend data
 * GET  /api/autoscan/:owner/:repo       — get auto-scan config
 * POST /api/autoscan/:owner/:repo       — set auto-scan schedule
 */

import crypto from 'crypto';
import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import type { SecurityAlert, TokenGitHubClient } from '../github-token.js';
import { getRedis, KEYS } from '../redis.js';
import { buildSbom } from './sbom.js';

// ── Scan lifecycle types ──────────────────────────────────────────────

export interface ScanRecord {
  scan_id: string;
  repo: string;
  status: 'queued' | 'scanning' | 'complete' | 'fixes_applied' | 'verified' | 'failed';
  started_at: string;
  completed_at?: string;
  alert_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixes_created: number;
  fixes_merged: number;
  fixes_verified: number;
  fixes_failed: number;
}

/** Verification result after fixes */
interface VerificationResult {
  previously: number;
  now: number;
  resolved: string[];
  remaining: string[];
}

// ── Helpers ───────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function emptyScanRecord(repo: string): ScanRecord {
  return {
    scan_id: crypto.randomUUID(),
    repo,
    status: 'scanning',
    started_at: new Date().toISOString(),
    alert_count: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    fixes_created: 0,
    fixes_merged: 0,
    fixes_verified: 0,
    fixes_failed: 0,
  };
}

function countSeverities(alerts: SecurityAlert[]): Pick<ScanRecord, 'critical' | 'high' | 'medium' | 'low'> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of alerts) {
    const sev = (a.severity ?? '').toLowerCase() as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }
  return counts;
}

/** Persist scan record to Redis with history tracking. */
async function saveScanRecord(scan: ScanRecord): Promise<void> {
  try {
    const redis = await getRedis();
    const json = JSON.stringify(scan);
    await redis.set(KEYS.scan(scan.scan_id), json);
    await redis.set(KEYS.scanLatest(scan.repo), json);
    // Push to per-repo scan history list (most recent first)
    await redis.lPush(KEYS.scanHistory(scan.repo), json);
    // Trim to keep last 100 scans per repo
    await redis.lTrim(KEYS.scanHistory(scan.repo), 0, 99);
  } catch (err) {
    console.warn('[redis] Failed to save scan record:', (err as Error).message);
  }
}

/** Record trend data point for the repo. */
async function recordTrend(scan: ScanRecord): Promise<void> {
  try {
    const redis = await getRedis();
    const point = JSON.stringify({
      scan_id: scan.scan_id,
      ts: scan.completed_at ?? scan.started_at,
      alert_count: scan.alert_count,
      critical: scan.critical,
      high: scan.high,
      medium: scan.medium,
      low: scan.low,
    });
    const score = new Date(scan.completed_at ?? scan.started_at).getTime();
    await redis.zAdd(KEYS.trend(scan.repo), { score, value: point });
    // Keep last 365 data points
    const total = await redis.zCard(KEYS.trend(scan.repo));
    if (total > 365) {
      await redis.zRemRangeByRank(KEYS.trend(scan.repo), 0, total - 366);
    }
  } catch (err) {
    console.warn('[redis] Failed to record trend:', (err as Error).message);
  }
}

/**
 * Re-scan after fixes to verify which CVEs were resolved.
 */
async function verifyFixScan(
  gh: TokenGitHubClient,
  owner: string,
  repo: string,
  previousAlerts: SecurityAlert[],
): Promise<VerificationResult> {
  // Wait for GitHub to process merges and update alert states
  await sleep(10000);

  const currentAlerts = await gh.getSecurityAlertsDetailed(owner, repo);
  const currentCves = new Set(currentAlerts.map((a) => a.cve ?? `alert-${a.alertNumber}`));
  const previousCves = previousAlerts.map((a) => a.cve ?? `alert-${a.alertNumber}`);

  const resolved = previousCves.filter((c) => !currentCves.has(c));
  const remaining = [...currentCves];

  return {
    previously: previousAlerts.length,
    now: currentAlerts.length,
    resolved,
    remaining,
  };
}

// ── Route registration ────────────────────────────────────────────────

export async function registerCveRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { github, state, gateway } = config;

  // Helper: safely add audit entry
  const audit = (entry: Record<string, unknown>) => {
    if (typeof state?.addAuditEntry === 'function') {
      try { state.addAuditEntry(entry as any); } catch { /* stub */ }
    }
  };

  // ── Scan with lifecycle tracking ────────────────────────────────────

  app.post<{
    Body: { owner?: string; repo?: string; severity?: string; dryRun?: boolean };
  }>('/api/cve/scan', async (req, reply) => {
    const { owner, repo, severity, dryRun } = req.body;

    if (!owner || !repo) {
      return reply.status(400).send({ error: 'owner and repo are required' });
    }

    const fullName = `${owner}/${repo}`;
    const scan = emptyScanRecord(fullName);

    // Persist initial scanning state
    await saveScanRecord(scan);

    // If gateway is available, use fabric CVE scan
    if (gateway?.available) {
      try {
        const routeResult = await gateway.router.route('cve_scan', {
          repos: [fullName],
          severity_threshold: (severity ?? 'HIGH').toUpperCase(),
          dry_run: dryRun ?? false,
        });
        const result = typeof routeResult.result === 'string'
          ? JSON.parse(routeResult.result)
          : routeResult.result;

        // Update scan record on completion
        const alerts: SecurityAlert[] = result.alerts ?? result.vulnerabilities ?? [];
        scan.status = 'complete';
        scan.completed_at = new Date().toISOString();
        scan.alert_count = alerts.length;
        Object.assign(scan, countSeverities(alerts));
        await saveScanRecord(scan);
        await recordTrend(scan);

        audit({ action: 'web_cve_scan', repo: fullName, result: 'success', scan_id: scan.scan_id, details: { source: 'gateway' } });
        return reply.send({ ...result, scan_id: scan.scan_id });
      } catch {
        // Fall through to REST
      }
    }

    // Fallback: Dependabot REST via TokenGitHubClient
    try {
      const alerts: SecurityAlert[] = await (github as any).getSecurityAlertsDetailed(owner, repo);
      const severityOrder = ['critical', 'high', 'medium', 'low'];
      const minSevIndex = (severity ?? 'all') === 'all'
        ? 4
        : severityOrder.indexOf((severity ?? 'high').toLowerCase());

      const filtered = alerts.filter((a) => {
        const idx = severityOrder.indexOf(a.severity?.toLowerCase());
        return idx >= 0 && idx <= minSevIndex;
      });

      // Complete scan record
      scan.status = 'complete';
      scan.completed_at = new Date().toISOString();
      scan.alert_count = filtered.length;
      Object.assign(scan, countSeverities(filtered));
      await saveScanRecord(scan);
      await recordTrend(scan);

      audit({ action: 'web_cve_scan', repo: fullName, result: 'success', scan_id: scan.scan_id, details: { source: 'dependabot', count: filtered.length } });

      return reply.send({
        repo: fullName,
        scan_id: scan.scan_id,
        source: 'dependabot',
        totalAlerts: filtered.length,
        alerts: filtered,
      });
    } catch (err: any) {
      // Mark scan as failed
      scan.status = 'failed';
      scan.completed_at = new Date().toISOString();
      await saveScanRecord(scan);

      return reply.status(500).send({
        error: `Scan failed: ${err.message}`,
        repo: fullName,
        scan_id: scan.scan_id,
      });
    }
  });

  // ── Get scan results for a repo ─────────────────────────────────────

  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/cve/results/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;

    try {
      const alerts = await (github as any).getSecurityAlertsDetailed(owner, repo);
      return reply.send({
        repo: `${owner}/${repo}`,
        totalAlerts: alerts.length,
        alerts,
      });
    } catch (err: any) {
      return reply.status(500).send({
        error: `Failed to fetch results: ${err.message}`,
        repo: `${owner}/${repo}`,
      });
    }
  });

  // ── Recent scans across all repos ───────────────────────────────────

  app.get<{
    Querystring: { limit?: string };
  }>('/api/scans/recent', async (req, reply) => {
    const limit = Math.min(parseInt(req.query.limit ?? '10', 10) || 10, 100);

    try {
      const redis = await getRedis();
      const keys: string[] = [];
      for await (const key of redis.scanIterator({ MATCH: 'gitsteer:scans:*', COUNT: 100 })) {
        if (Array.isArray(key)) {
          keys.push(...key);
        } else {
          keys.push(key);
        }
      }

      const allScans: ScanRecord[] = [];
      for (const key of keys) {
        const items = await redis.lRange(key, 0, 4); // Last 5 per repo
        for (const raw of items) {
          try { allScans.push(JSON.parse(raw)); } catch { /* skip corrupt */ }
        }
      }

      // Sort by started_at descending
      allScans.sort((a, b) => b.started_at.localeCompare(a.started_at));

      return reply.send({
        count: Math.min(allScans.length, limit),
        scans: allScans.slice(0, limit),
      });
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch recent scans: ${err.message}` });
    }
  });

  // ── Get single scan by ID ──────────────────────────────────────────

  app.get<{
    Params: { scanId: string };
  }>('/api/scans/:scanId', async (req, reply) => {
    const { scanId } = req.params;

    try {
      const redis = await getRedis();
      const raw = await redis.get(KEYS.scan(scanId));

      if (!raw) {
        return reply.status(404).send({ error: 'Scan not found', scan_id: scanId });
      }

      return reply.send(JSON.parse(raw));
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch scan: ${err.message}` });
    }
  });

  // ── Verify (body-based, existing endpoint) ──────────────────────────

  app.post<{
    Body: { owner: string; repo: string; previousAlerts?: SecurityAlert[] };
  }>('/api/cve/verify', async (req, reply) => {
    const { owner, repo, previousAlerts } = req.body;

    if (!owner || !repo) {
      return reply.status(400).send({ error: 'owner and repo are required' });
    }

    const gh = github as unknown as TokenGitHubClient;

    try {
      const baseline = previousAlerts ?? await gh.getSecurityAlertsDetailed(owner, repo);
      const verification = await verifyFixScan(gh, owner, repo, baseline);

      return reply.send(verification);
    } catch (err: any) {
      return reply.status(500).send({ error: err.message });
    }
  });

  // ── Verify (param-based with Redis tracking) ───────────────────────

  app.post<{
    Params: { owner: string; repo: string };
  }>('/api/cve/verify/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;
    const gh = github as unknown as TokenGitHubClient;

    try {
      // Get previous scan for comparison
      let previousScan: ScanRecord | null = null;
      try {
        const redis = await getRedis();
        const raw = await redis.get(KEYS.scanLatest(fullName));
        if (raw) previousScan = JSON.parse(raw);
      } catch { /* no previous scan */ }

      // Run fresh scan
      const alerts: SecurityAlert[] = await gh.getSecurityAlertsDetailed(owner, repo);
      const sevCounts = countSeverities(alerts);

      const verifyScan = emptyScanRecord(fullName);
      verifyScan.status = 'verified';
      verifyScan.completed_at = new Date().toISOString();
      verifyScan.alert_count = alerts.length;
      Object.assign(verifyScan, sevCounts);

      // Compare with previous
      if (previousScan) {
        verifyScan.fixes_verified = Math.max(0, previousScan.alert_count - alerts.length);
        verifyScan.fixes_failed = Math.max(0, alerts.length - (previousScan.alert_count - previousScan.fixes_created));
      }

      await saveScanRecord(verifyScan);
      await recordTrend(verifyScan);

      // If all clear, generate a real CycloneDX SBOM snapshot (ADR-004 C-004-002)
      let sbomGenerated = false;
      if (alerts.length === 0) {
        try {
          const redis = await getRedis();
          const snapshot = await buildSbom((gh as any).getOctokit(), owner, repo);
          await redis.set(KEYS.sbom(fullName), JSON.stringify(snapshot));
          sbomGenerated = true;
        } catch { /* non-fatal */ }
      }

      audit({ action: 'web_cve_verify', repo: fullName, result: 'success', scan_id: verifyScan.scan_id });

      return reply.send({
        repo: fullName,
        scan_id: verifyScan.scan_id,
        status: verifyScan.status,
        current: {
          alert_count: alerts.length,
          ...sevCounts,
        },
        previous: previousScan ? {
          scan_id: previousScan.scan_id,
          alert_count: previousScan.alert_count,
          critical: previousScan.critical,
          high: previousScan.high,
          medium: previousScan.medium,
          low: previousScan.low,
        } : null,
        delta: previousScan ? {
          resolved: Math.max(0, previousScan.alert_count - alerts.length),
          new: Math.max(0, alerts.length - previousScan.alert_count),
        } : null,
        sbom_generated: sbomGenerated,
      });
    } catch (err: any) {
      return reply.status(500).send({ error: `Verification failed: ${err.message}`, repo: fullName });
    }
  });

  // ── Queue ───────────────────────────────────────────────────────────

  app.get<{
    Querystring: { status?: string; severity?: string; repo?: string; limit?: string };
  }>('/api/cve/queue', async (_req, reply) => {
    if (gateway?.available) {
      try {
        const routeResult = await gateway.router.route('cve_queue_list', { status: 'pending', limit: 50 });
        const result = typeof routeResult.result === 'string' ? JSON.parse(routeResult.result) : routeResult.result;
        return reply.send(result);
      } catch { /* fall through */ }
    }

    return reply.send({ source: 'none', count: 0, queue: [], note: 'Scan a repo to populate the queue' });
  });

  // ── Trends ──────────────────────────────────────────────────────────

  app.get<{
    Params: { owner: string; repo: string };
    Querystring: { days?: string };
  }>('/api/trends/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;
    const days = Math.min(parseInt(req.query.days ?? '90', 10) || 90, 365);
    const since = Date.now() - days * 24 * 60 * 60 * 1000;

    try {
      const redis = await getRedis();
      const raw = await redis.zRangeByScore(KEYS.trend(fullName), since, '+inf');

      const points = raw.map((r) => {
        try { return JSON.parse(r); } catch { return null; }
      }).filter(Boolean);

      return reply.send({
        repo: fullName,
        days,
        count: points.length,
        points,
      });
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch trends: ${err.message}` });
    }
  });

  // ── Auto-scan config ────────────────────────────────────────────────

  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/autoscan/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    try {
      const redis = await getRedis();
      const raw = await redis.get(KEYS.autoScan(fullName));

      if (!raw) {
        return reply.send({
          repo: fullName,
          schedule: 'off',
          configured: false,
        });
      }

      return reply.send(JSON.parse(raw));
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch auto-scan config: ${err.message}` });
    }
  });

  app.post<{
    Params: { owner: string; repo: string };
    Body: { schedule: 'daily' | 'weekly' | 'off'; severity?: string };
  }>('/api/autoscan/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const { schedule, severity } = req.body;
    const fullName = `${owner}/${repo}`;

    if (!schedule || !['daily', 'weekly', 'off'].includes(schedule)) {
      return reply.status(400).send({ error: 'schedule must be: daily, weekly, or off' });
    }

    try {
      const redis = await getRedis();
      const configObj = {
        repo: fullName,
        schedule,
        severity: severity ?? 'high',
        configured: schedule !== 'off',
        updated_at: new Date().toISOString(),
      };

      if (schedule === 'off') {
        await redis.del(KEYS.autoScan(fullName));
      } else {
        await redis.set(KEYS.autoScan(fullName), JSON.stringify(configObj));
      }

      return reply.send(configObj);
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to save auto-scan config: ${err.message}` });
    }
  });
}
