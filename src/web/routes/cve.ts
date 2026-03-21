/**
 * CVE scanning routes
 *
 * POST /api/cve/scan              — trigger CVE scan for a repo
 * GET  /api/cve/results/:owner/:repo — get scan results
 * POST /api/cve/triage/:cveId     — triage a CVE (confirm, dismiss, fix)
 * POST /api/cve/fix               — create a fix PR for a CVE
 * GET  /api/cve/queue             — get pending CVE queue
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';

export async function registerCveRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { github, state, gateway } = config;

  // Trigger a CVE scan for a repo (or all managed repos)
  app.post<{
    Body: {
      owner?: string;
      repo?: string;
      severity?: string;
      dryRun?: boolean;
    };
  }>('/api/cve/scan', async (req, reply) => {
    const { owner, repo, severity, dryRun } = req.body;

    // If gateway is available, use fabric CVE scan
    if (gateway?.available) {
      const scanArgs: Record<string, unknown> = {
        severity_threshold: (severity ?? 'HIGH').toUpperCase(),
        dry_run: dryRun ?? false,
      };
      if (owner && repo) {
        scanArgs.repos = [`${owner}/${repo}`];
      }

      const routeResult = await gateway.router.route('cve_scan', scanArgs);
      const result = typeof routeResult.result === 'string'
        ? JSON.parse(routeResult.result)
        : routeResult.result;

      state.addAuditEntry({
        action: 'web_cve_scan',
        repo: owner && repo ? `${owner}/${repo}` : undefined,
        result: 'success',
        details: { source: 'gateway', severity, dryRun },
      });

      return reply.send(result);
    }

    // Fallback: use Dependabot REST via GitHub client
    if (!owner || !repo) {
      return reply.status(400).send({
        error: 'owner and repo are required when fabric gateway is unavailable',
      });
    }

    const alerts = await github.getSecurityAlertsDetailed(owner, repo);
    const severityOrder = ['critical', 'high', 'medium', 'low'];
    const minSevIndex = (severity ?? 'all') === 'all'
      ? 4
      : severityOrder.indexOf((severity ?? 'high').toLowerCase());

    const filtered = alerts.filter((a) => {
      const idx = severityOrder.indexOf(a.severity);
      return idx >= 0 && idx <= minSevIndex;
    });

    state.addAuditEntry({
      action: 'web_cve_scan',
      repo: `${owner}/${repo}`,
      result: 'success',
      details: { source: 'dependabot_rest', severity, alerts: filtered.length },
    });

    return reply.send({
      repo: `${owner}/${repo}`,
      source: 'dependabot_rest',
      totalAlerts: filtered.length,
      alerts: filtered,
    });
  });

  // Get scan results for a specific repo
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/cve/results/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    // Pull RFCs (which contain vulnerability data) for this repo
    const rfcs = state.getRfcs({ repo: fullName });

    // Pull last sweep time
    const lastSwept = state.getLastSweptAt(fullName);

    return reply.send({
      repo: fullName,
      lastSwept,
      rfcCount: rfcs.length,
      rfcs: rfcs.map((r) => ({
        issueNumber: r.issueNumber,
        issueUrl: r.issueUrl,
        severity: r.severity,
        status: r.status,
        vulnerabilities: r.vulnerabilities,
        prNumber: r.prNumber,
        prUrl: r.prUrl,
        fixedAt: r.fixedAt,
        mttr: r.mttr,
      })),
    });
  });

  // Triage a CVE
  app.post<{
    Params: { cveId: string };
    Body: {
      action: 'confirm' | 'dismiss' | 'fix';
      reason?: string;
      owner?: string;
      repo?: string;
    };
  }>('/api/cve/triage/:cveId', async (req, reply) => {
    const { cveId } = req.params;
    const { action, reason, owner, repo } = req.body;

    if (!action || !['confirm', 'dismiss', 'fix'].includes(action)) {
      return reply.status(400).send({ error: 'action must be one of: confirm, dismiss, fix' });
    }

    // If gateway is available, use fabric CVE triage
    if (gateway?.available) {
      try {
        const routeResult = await gateway.router.route('cve_triage', {
          cve_id: cveId,
          action,
          reason,
        });
        const result = typeof routeResult.result === 'string'
          ? JSON.parse(routeResult.result)
          : routeResult.result;

        state.addAuditEntry({
          action: 'web_cve_triage',
          repo: owner && repo ? `${owner}/${repo}` : undefined,
          result: 'success',
          details: { cveId, triageAction: action, reason },
        });

        return reply.send(result);
      } catch (err: unknown) {
        return reply.status(500).send({
          error: `Triage failed: ${(err as Error).message}`,
          cveId,
        });
      }
    }

    // Fallback: dismiss via Dependabot REST
    if (action === 'dismiss' && owner && repo) {
      // No direct CVE-to-alert-ID mapping without gateway; return guidance
      return reply.status(501).send({
        error: 'CVE triage requires the fabric gateway for full functionality. Use the MCP security_dismiss tool with the alert ID instead.',
        cveId,
      });
    }

    return reply.status(501).send({
      error: 'CVE triage requires the fabric gateway',
      cveId,
    });
  });

  // Create a fix PR for a CVE
  app.post<{
    Body: {
      owner: string;
      repo: string;
      severity?: string;
      dryRun?: boolean;
    };
  }>('/api/cve/fix', async (req, reply) => {
    const { owner, repo, severity, dryRun } = req.body;

    if (!owner || !repo) {
      return reply.status(400).send({ error: 'owner and repo are required' });
    }

    const fullName = `${owner}/${repo}`;

    // Use the same logic as security_fix_pr MCP tool
    const alerts = await github.getSecurityAlertsDetailed(owner, repo);
    const severityOrder = ['critical', 'high', 'medium', 'low'];
    const minSevIndex = (severity ?? 'critical') === 'all'
      ? 4
      : severityOrder.indexOf((severity ?? 'critical').toLowerCase());

    const toFix = alerts.filter((a) => {
      const idx = severityOrder.indexOf(a.severity);
      return idx >= 0 && idx <= minSevIndex && a.fixVersion;
    });

    if (toFix.length === 0) {
      return reply.send({
        message: 'No fixable vulnerabilities found at the specified severity level',
        severity: severity ?? 'critical',
        totalAlerts: alerts.length,
      });
    }

    if (dryRun) {
      return reply.send({
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
      });
    }

    const result = await github.dispatchSecurityFix(fullName, {
      severity: (severity ?? 'critical') as 'critical' | 'high' | 'medium' | 'low' | 'all',
      dryRun: false,
      jobId: `web-fix-${repo}-${Date.now()}`,
    });

    state.addAuditEntry({
      action: 'web_cve_fix',
      repo: fullName,
      result: 'success',
      details: {
        jobId: result.jobId,
        severity: severity ?? 'critical',
        vulnerabilitiesFound: toFix.length,
      },
    });

    return reply.send({
      success: true,
      jobId: result.jobId,
      targetRepo: fullName,
      vulnerabilitiesFound: toFix.length,
    });
  });

  // Get pending CVE queue
  app.get<{
    Querystring: {
      status?: string;
      severity?: string;
      repo?: string;
      limit?: string;
    };
  }>('/api/cve/queue', async (req, reply) => {
    const { status, severity, repo, limit } = req.query;

    // If gateway is available, use fabric CVE queue
    if (gateway?.available) {
      const routeResult = await gateway.router.route('cve_queue_list', {
        status: status ?? 'pending',
        severity_min: (severity ?? 'LOW').toUpperCase(),
        repo,
        limit: limit ? parseInt(limit, 10) : 50,
      });
      const result = typeof routeResult.result === 'string'
        ? JSON.parse(routeResult.result)
        : routeResult.result;

      return reply.send(result);
    }

    // Fallback: return RFCs from state as a pseudo-queue
    const rfcs = state.getRfcs({
      repo,
      status: (status as 'open' | 'in_progress' | 'fixed' | 'closed') ?? undefined,
    });

    return reply.send({
      source: 'state_rfcs',
      count: rfcs.length,
      entries: rfcs.map((r) => ({
        repo: r.repo,
        issueNumber: r.issueNumber,
        issueUrl: r.issueUrl,
        severity: r.severity,
        status: r.status,
        vulnerabilities: r.vulnerabilities,
        prNumber: r.prNumber,
        prUrl: r.prUrl,
      })),
    });
  });
}
