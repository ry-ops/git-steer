/**
 * Operations tools: steer_status, steer_sync, steer_logs, config_show,
 * config_add_repo, config_remove_repo, ops_metrics, dashboard_generate,
 * report_generate, workflow_status
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';
import { generateReport } from '../../reports/templates.js';
import { generateDashboardHtml } from '../../dashboard/templates.js';

export function getTools(): Tool[] {
  return [
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
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'steer_status': return handleSteerStatus(args, deps);
    case 'steer_sync': return handleSteerSync(args, deps);
    case 'steer_logs': return handleSteerLogs(args, deps);
    case 'config_show': return handleConfigShow(args, deps);
    case 'config_add_repo': return handleConfigAddRepo(args, deps);
    case 'config_remove_repo': return handleConfigRemoveRepo(args, deps);
    case 'ops_metrics': return handleOpsMetrics(args, deps);
    case 'report_generate': return handleReportGenerate(args, deps);
    case 'dashboard_generate': return handleDashboardGenerate(args, deps);
    case 'workflow_status': return handleWorkflowStatus(args, deps);
    default: return null;
  }
}

async function handleSteerStatus(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  // If cache is stale (>30 min) or missing, refresh inline
  const cacheAgeMs = deps.rateLimitCache
    ? Date.now() - deps.rateLimitCache.fetchedAt.getTime()
    : Infinity;
  if (cacheAgeMs > 30 * 60 * 1000) {
    await deps.refreshRateLimit();
  }

  const rl = deps.rateLimitCache;
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
      authenticated: deps.github.isAuthenticated(),
      rateLimit: rateLimitInfo,
    },
    state: {
      lastSync: deps.state.getLastSync()?.toISOString(),
      dirty: deps.state.isDirty(),
      managedRepos: deps.state.getManagedRepos().length,
      scheduledJobs: deps.state.getScheduledJobs().length,
    },
  };
}

async function handleSteerSync(_args: Record<string, any>, deps: ToolDeps): Promise<any> {
  await deps.state.save();
  return { synced: true, timestamp: new Date().toISOString() };
}

async function handleSteerLogs(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  let logs = deps.state.getRecentAudit(args.limit || 20);

  if (args.action) {
    logs = logs.filter((l) => l.action === args.action);
  }

  return logs;
}

async function handleConfigShow(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const section = args.section || 'all';
  const result: Record<string, any> = {};

  if (section === 'all' || section === 'repos') {
    result.repos = deps.state.getManagedRepos();
  }
  if (section === 'all' || section === 'policies') {
    result.policies = deps.state.getPolicies();
  }
  if (section === 'all' || section === 'schedules') {
    result.schedules = deps.state.getScheduledJobs();
  }

  return result;
}

async function handleConfigAddRepo(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  deps.state.addManagedRepo({
    owner: args.owner,
    name: args.name,
    policies: args.policies || [],
  });

  if (args.name !== '*') {
    try {
      await deps.github.enableVulnerabilityAlerts(args.owner, args.name);
      await deps.github.enableAutomatedSecurityFixes(args.owner, args.name);
    } catch {
      // Non-fatal
    }
  }

  return { added: true, repo: `${args.owner}/${args.name}`, dependabotEnabled: args.name !== '*' };
}

async function handleConfigRemoveRepo(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  deps.state.removeManagedRepo(args.owner, args.name);
  return { removed: true, repo: `${args.owner}/${args.name}` };
}

async function handleOpsMetrics(args: Record<string, any>, deps: ToolDeps): Promise<any> {
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
  const audit = deps.state.getRecentAudit(10000).filter((e) => e.ts >= sinceIso);

  const alertEntries = audit.filter((e) => e.action === 'pr_dedup_create' || e.action === 'pr_dedup_check');
  const alertsPerDay = alertEntries.length / Math.max(1, (now.getTime() - since.getTime()) / (24 * 60 * 60 * 1000));

  const dedupChecks = audit.filter((e) => e.action === 'pr_dedup_create');
  const dedupHits = dedupChecks.filter((e) => e.result === 'dedup_hit');
  const dedupHitRate = dedupChecks.length > 0 ? dedupHits.length / dedupChecks.length : 0;

  const mergeAttempts = audit.filter((e) => e.action === 'fabric_git_merge_pull_request');
  const mergeSuccesses = mergeAttempts.filter((e) => e.result === 'success');
  const mergeSuccessRate = mergeAttempts.length > 0 ? mergeSuccesses.length / mergeAttempts.length : 0;

  const remediations = audit.filter((e) => e.action === 'oomkill_remediate' && e.result === 'pr_created');

  const oomEvents = audit.filter((e) => e.action === 'oomkill_detect');
  const oomTotal = oomEvents.reduce((sum, e) => sum + (e.details?.oomPodsFound || 0), 0);

  const certChecks = audit.filter((e) => e.action === 'cert_check');
  const certRenewals = audit.filter((e) => e.action === 'cert_renew');

  const securityMetrics = deps.state.getMetrics({
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

async function handleReportGenerate(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const template = args.template || 'executive-summary';
  const dateRange = args.dateRange;
  const format = args.format || 'markdown';

  const metrics = deps.state.getMetrics(dateRange);
  const rfcs = deps.state.getRfcs();
  const quality = deps.state.getQualityResults();

  const report = generateReport(template, { metrics, rfcs, quality, dateRange });

  if (format === 'json') {
    return { template, metrics, rfcs: rfcs.length, qualityResults: quality.length };
  }

  if (args.commitToRepo) {
    const managedRepos = deps.state.getManagedRepos();
    const stateRepoName = 'git-steer-state';
    const owner = managedRepos[0]?.owner || 'ry-ops';
    const fileName = `reports/${template}-${new Date().toISOString().split('T')[0]}.md`;

    await deps.github.updateFileContent(
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

async function handleDashboardGenerate(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const dateRange = args.dateRange;
  const metrics = deps.state.getMetrics(dateRange);
  const rfcs = deps.state.getRfcs(args.repo ? { repo: args.repo } : undefined);
  const quality = deps.state.getQualityResults(args.repo ? { repo: args.repo } : undefined);

  const html = generateDashboardHtml({ metrics, rfcs, quality, dateRange });

  const owner = 'ry-ops';
  const stateRepo = 'git-steer-state';

  const commitResult = await deps.github.commitFiles(owner, stateRepo, {
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

async function handleWorkflowStatus(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const workflowFile = args.workflow === 'heartbeat' ? 'heartbeat.yml' : 'security-fix.yml';
  const runs = await deps.github.getWorkflowRuns('ry-ops', 'git-steer', workflowFile, {
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
