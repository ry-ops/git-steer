/**
 * Security tools: security_alerts, security_digest, security_scan,
 * security_sweep, security_dismiss, security_enforce, security_fix_pr
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps } from './types.js';
import { validateVexInput } from '../../core/vex.js';
import type { VexEntry } from '../../core/vex.js';

export function getTools(): Tool[] {
  return [
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
          confirm: { type: 'string', description: "Safety confirmation. Must be exactly 'CONFIRM_SECURITY_DISMISS' to proceed." },
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
      name: 'security_enforce',
      description: 'Ensure Dependabot vulnerability alerts and automated security fixes are enabled on all managed repos (or a specific repo)',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repo owner (omit to enforce on all managed repos)' },
          repo: { type: 'string', description: 'Repo name (omit to enforce on all managed repos)' },
        },
      },
    },
    {
      name: 'sbom_generate',
      description: 'Generate an SPDX Software Bill of Materials (SBOM) for a repository using GitHub\'s dependency graph',
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
      name: 'vex_set',
      description: 'Set OpenVEX status on a CVE finding (ADR-004). Persisted to the git-steer-state _vex store. not_affected requires a justification; affected requires an actionStatement.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          cveId: { type: 'string', description: 'CVE or GHSA identifier, e.g. CVE-2024-1234 or GHSA-xxxx-xxxx-xxxx' },
          status: {
            type: 'string',
            enum: ['not_affected', 'affected', 'fixed', 'under_investigation'],
          },
          justification: {
            type: 'string',
            enum: ['component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist'],
            description: 'OpenVEX justification — REQUIRED when status is not_affected',
          },
          actionStatement: { type: 'string', description: 'REQUIRED when status is affected — the mitigation or acceptance rationale' },
          impactStatement: { type: 'string', description: 'Optional impact detail for not_affected' },
          productPurl: { type: 'string', description: 'PURL of the affected SBOM component, e.g. pkg:npm/esbuild@0.25.12 (links to the SBOM, C-004-004)' },
          detail: { type: 'string', description: 'Optional free-text rationale' },
        },
        required: ['owner', 'repo', 'cveId', 'status'],
      },
    },
    {
      name: 'vex_history',
      description: 'Look up VEX history from the append-only vex.jsonl ledger (who/what/when, before -> after). Filter by repo and/or cveId. Returns chronological history plus the current status.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Optional — limit to a repo (with repo)' },
          repo: { type: 'string', description: 'Optional — limit to a repo (with owner)' },
          cveId: { type: 'string', description: 'Optional — limit to a single CVE/finding id' },
          status: { type: 'string', description: 'Optional — filter to a status', enum: ['not_affected', 'affected', 'fixed', 'under_investigation'] },
        },
      },
    },
    {
      name: 'policy_eval',
      description: 'Evaluate managed repos against security policies (Dependabot, secret scanning, branch protection, advanced security). Reports pass/fail per control.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Limit to a single owner' },
          repo: { type: 'string', description: 'Limit to a single repo (requires owner)' },
          controls: {
            type: 'array',
            items: {
              type: 'string',
              enum: ['vulnerability_alerts', 'secret_scanning', 'secret_scanning_push_protection', 'advanced_security', 'branch_protection'],
            },
            description: 'Controls to evaluate. Omit to check all.',
          },
        },
      },
    },
    {
      name: 'attestation_list',
      description: 'List GitHub Artifact Attestations for a repository',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          subjectDigest: { type: 'string', description: 'Optional sha256:... digest to filter to a specific artifact' },
        },
        required: ['owner', 'repo'],
      },
    },
    {
      name: 'security_sweep',
      description: 'Autonomous security sweep: scans repos for CVEs, creates RFC issues with ITIL-formatted change records, and dispatches a GitHub Actions workflow to fix vulnerabilities and create PRs — all in one call. Supports chunked execution: set chunkSize to process a subset per call and call again with resume:true to continue.',
      inputSchema: {
        type: 'object',
        properties: {
          severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'all'],
            default: 'critical',
            description: 'Minimum severity to include',
          },
          repos: {
            type: 'array',
            items: { type: 'string' },
            description: 'Specific repos to sweep (owner/repo). Omit to sweep all managed repos.',
          },
          dryRun: {
            type: 'boolean',
            default: false,
            description: 'Scan and report only, do not create issues or dispatch fixes',
          },
          skipRfc: {
            type: 'boolean',
            default: false,
            description: 'Skip RFC issue creation (dispatch fix workflow directly)',
          },
          chunkSize: {
            type: 'number',
            description: 'Max repos to process per call. Omit to process all in one shot. When set, a cursor is persisted and the next call with resume:true continues where this left off.',
          },
          resume: {
            type: 'boolean',
            default: false,
            description: 'Resume a previously chunked sweep from the saved cursor. Ignores repos/severity/skipRfc (carried from the original call).',
          },
          skipRecentHours: {
            type: 'number',
            description: 'Skip repos swept within this many hours (default: no skip). Useful for polling fallback — set to 6 to avoid re-scanning repos touched in the last 6h.',
          },
        },
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'security_alerts': return handleSecurityAlerts(args, deps);
    case 'security_dismiss': return handleSecurityDismiss(args, deps);
    case 'security_digest': return handleSecurityDigest(args, deps);
    case 'security_scan': return handleSecurityScan(args, deps);
    case 'security_fix_pr': return handleSecurityFixPr(args, deps);
    case 'security_enforce': return handleSecurityEnforce(args, deps);
    case 'security_sweep': return handleSecuritySweep(args, deps);
    case 'sbom_generate': return handleSbomGenerate(args, deps);
    case 'vex_set': return handleVexSet(args, deps);
    case 'vex_history': return handleVexHistory(args, deps);
    case 'policy_eval': return handlePolicyEval(args, deps);
    case 'attestation_list': return handleAttestationList(args, deps);
    default: return null;
  }
}

async function handleSecurityAlerts(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const alerts = await deps.github.getSecurityAlerts(args.owner, args.repo);

  if (args.severity && args.severity !== 'all') {
    return alerts.filter((a) => a.severity === args.severity);
  }

  return alerts;
}

async function handleSecurityDismiss(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  await deps.github.dismissSecurityAlert(
    args.owner,
    args.repo,
    args.alertId,
    args.reason
  );
  return { dismissed: true, alertId: args.alertId };
}

async function handleSecurityDigest(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const managedRepos = deps.state.getManagedRepos();
  const digest: Record<string, any[]> = {};

  await Promise.all(
    managedRepos
      .filter((repo) => repo.name !== '*')
      .map((repo) =>
        deps.readLimit(async () => {
          try {
            const alerts = await deps.github.getSecurityAlerts(repo.owner, repo.name);
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
        })
      )
  );

  return digest;
}

async function handleSecurityScan(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const repos = args.repo === '*' || !args.repo
    ? await deps.github.listRepos()
    : [{ owner: args.owner, name: args.repo, fullName: `${args.owner}/${args.repo}` }];

  const results: Record<string, any[]> = {};
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const minSeverityIndex = args.severity === 'all' ? 4 : severityOrder.indexOf(args.severity);

  await Promise.all(
    repos.map((repo) =>
      deps.readLimit(async () => {
        try {
          const alerts = await deps.github.getSecurityAlertsDetailed(
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
      })
    )
  );

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

async function handleSecurityFixPr(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const alerts = await deps.github.getSecurityAlertsDetailed(args.owner, args.repo);
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

  const targetRepo = `${args.owner}/${args.repo}`;
  const result = await deps.github.dispatchSecurityFix(targetRepo, {
    severity: args.severity || 'critical',
    dryRun: false,
    jobId: `fix-${args.repo}-${Date.now()}`,
  });

  deps.state.addAuditEntry({
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

async function handleSecurityEnforce(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  let targetRepos: Array<{ owner: string; name: string }>;

  if (args.owner && args.repo) {
    targetRepos = [{ owner: args.owner, name: args.repo }];
  } else {
    const managed = deps.state.getManagedRepos();
    if (managed.length === 0) {
      const allRepos = await deps.github.listRepos();
      targetRepos = allRepos.map((r) => ({ owner: r.owner, name: r.name }));
    } else {
      targetRepos = managed
        .filter((r) => r.name !== '*')
        .map((r) => ({ owner: r.owner, name: r.name }));
    }
  }

  const results: Array<{
    repo: string;
    alerts: string;
    autoFix: string;
  }> = [];

  for (const repo of targetRepos) {
    const repoFullName = `${repo.owner}/${repo.name}`;
    let alertsStatus = 'unknown';
    let autoFixStatus = 'unknown';

    try {
      await deps.github.enableVulnerabilityAlerts(repo.owner, repo.name);
      alertsStatus = 'enabled';
    } catch (error: any) {
      alertsStatus = `failed: ${error.message}`;
    }

    try {
      await deps.github.enableAutomatedSecurityFixes(repo.owner, repo.name);
      autoFixStatus = 'enabled';
    } catch (error: any) {
      autoFixStatus = `failed: ${error.message}`;
    }

    results.push({ repo: repoFullName, alerts: alertsStatus, autoFix: autoFixStatus });
  }

  return {
    enforced: results.length,
    results,
  };
}

async function handleSbomGenerate(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const sbom = await deps.github.getSbom(args.owner, args.repo);
  return {
    repo: `${args.owner}/${args.repo}`,
    sbom,
  };
}

async function handleVexSet(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const entry: VexEntry = {
    cve_id: args.cveId,
    repo: `${args.owner}/${args.repo}`,
    product_purl: args.productPurl ?? undefined,
    status: args.status,
    justification: args.justification ?? undefined,
    action_statement: args.actionStatement ?? undefined,
    impact_statement: args.impactStatement ?? undefined,
    detail: args.detail ?? undefined,
    created_at: new Date().toISOString(),
    updated_by: 'git-steer',
  };

  // Enforce ADR-004 C-004-003 before persisting (also enforced in setVexStatus).
  const error = validateVexInput(entry);
  if (error) {
    deps.state.addAuditEntry({
      action: 'vex_set', repo: entry.repo, result: 'failure',
      details: { cveId: args.cveId, status: args.status, error },
    });
    return { success: false, error };
  }

  deps.state.setVexStatus(entry);
  deps.state.addAuditEntry({
    action: 'vex_set',
    repo: entry.repo,
    result: 'success',
    details: { cveId: args.cveId, status: args.status },
  });

  return { success: true, entry };
}

async function handleVexHistory(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const repo = args.owner && args.repo ? `${args.owner}/${args.repo}` : undefined;
  const history = deps.state.getVexLedger({ repo, cveId: args.cveId, status: args.status });

  // Current status for the queried scope (from the _vex map).
  const all = deps.state.getAllVex();
  const current = Object.values(all).filter((e: any) =>
    (!repo || e.repo === repo) && (!args.cveId || e.cve_id === args.cveId),
  );

  return {
    filter: { repo: repo ?? 'all', cveId: args.cveId ?? 'all', status: args.status ?? 'all' },
    changes: history.length,
    history,
    current,
  };
}

async function handlePolicyEval(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const ALL_CONTROLS = ['vulnerability_alerts', 'secret_scanning', 'secret_scanning_push_protection', 'advanced_security', 'branch_protection'];
  const controls: string[] = args.controls && args.controls.length > 0 ? args.controls : ALL_CONTROLS;

  let targetRepos: Array<{ owner: string; name: string; fullName: string }>;

  if (args.owner && args.repo) {
    targetRepos = [{ owner: args.owner, name: args.repo, fullName: `${args.owner}/${args.repo}` }];
  } else {
    const managed = deps.state.getManagedRepos().filter((r) => r.name !== '*');
    if (managed.length === 0) {
      const fetched = await deps.github.listRepos();
      targetRepos = fetched.map((r) => ({ owner: r.owner, name: r.name, fullName: r.fullName }));
    } else {
      targetRepos = managed.map((r) => ({ owner: r.owner, name: r.name, fullName: `${r.owner}/${r.name}` }));
    }
  }

  const results: Array<{
    repo: string;
    pass: string[];
    fail: string[];
    controls: Record<string, boolean>;
  }> = [];

  await Promise.all(
    targetRepos.map((repo) =>
      deps.readLimit(async () => {
        try {
          const security = await deps.github.getRepoSecuritySettings(repo.owner, repo.name);

          const controlMap: Record<string, boolean> = {};

          if (controls.includes('vulnerability_alerts')) {
            controlMap.vulnerability_alerts = security.vulnerabilityAlerts;
          }
          if (controls.includes('secret_scanning')) {
            controlMap.secret_scanning = security.secretScanning;
          }
          if (controls.includes('secret_scanning_push_protection')) {
            controlMap.secret_scanning_push_protection = security.secretScanningPushProtection;
          }
          if (controls.includes('advanced_security')) {
            controlMap.advanced_security = security.advancedSecurity;
          }
          if (controls.includes('branch_protection')) {
            // Check if the default branch is protected
            try {
              const branches = await deps.github.listBranchesGraphQL(repo.owner, repo.name);
              const defaultBranchProtected = branches.some((b) => b.protected);
              controlMap.branch_protection = defaultBranchProtected;
            } catch {
              controlMap.branch_protection = false;
            }
          }

          const pass = Object.entries(controlMap).filter(([, v]) => v).map(([k]) => k);
          const fail = Object.entries(controlMap).filter(([, v]) => !v).map(([k]) => k);

          results.push({ repo: repo.fullName, pass, fail, controls: controlMap });
        } catch {
          results.push({
            repo: repo.fullName,
            pass: [],
            fail: controls,
            controls: Object.fromEntries(controls.map((c) => [c, false])),
          });
        }
      })
    )
  );

  const compliant = results.filter((r) => r.fail.length === 0).length;
  const nonCompliant = results.filter((r) => r.fail.length > 0).length;

  return {
    summary: {
      reposEvaluated: results.length,
      compliant,
      nonCompliant,
    },
    results,
  };
}

async function handleAttestationList(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const attestations = await deps.github.listAttestations(args.owner, args.repo, args.subjectDigest);
  return {
    repo: `${args.owner}/${args.repo}`,
    count: attestations.length,
    attestations,
  };
}

async function handleSecuritySweep(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const severityOrder = ['critical', 'high', 'medium', 'low'];

  let cursor = deps.state.getSweepCursor();
  let allRepos: Array<{ owner: string; name: string; fullName: string }>;
  let minSev: string;
  let effectiveSkipRfc: boolean;
  let effectiveDryRun: boolean;

  if (args.resume && cursor) {
    allRepos = cursor.repos;
    minSev = cursor.params.severity;
    effectiveSkipRfc = cursor.params.skipRfc;
    effectiveDryRun = cursor.params.dryRun;
  } else {
    minSev = args.severity || 'critical';
    effectiveSkipRfc = args.skipRfc || false;
    effectiveDryRun = args.dryRun || false;

    if (args.repos && args.repos.length > 0) {
      allRepos = args.repos.map((r: string) => {
        const [owner, name] = r.split('/');
        return { owner, name, fullName: r };
      });
    } else {
      const managed = deps.state.getManagedRepos();
      if (managed.length === 0) {
        const fetched = await deps.github.listRepos();
        allRepos = fetched.map((r) => ({ owner: r.owner, name: r.name, fullName: r.fullName }));
      } else {
        allRepos = managed
          .filter((r) => r.name !== '*')
          .map((r) => ({ owner: r.owner, name: r.name, fullName: `${r.owner}/${r.name}` }));
      }
    }

    if (args.chunkSize) {
      cursor = {
        repos: allRepos,
        nextIndex: 0,
        startedAt: new Date().toISOString(),
        params: { severity: minSev, skipRfc: effectiveSkipRfc, dryRun: effectiveDryRun },
      };
    } else {
      deps.state.clearSweepCursor();
      cursor = null;
    }
  }

  const minSevIndex = minSev === 'all' ? 4 : severityOrder.indexOf(minSev);

  const startIndex = cursor?.nextIndex ?? 0;
  const chunkSize = args.chunkSize ?? allRepos.length;
  let slicedRepos = allRepos.slice(startIndex, startIndex + chunkSize);

  if (args.skipRecentHours && args.skipRecentHours > 0) {
    const cutoff = Date.now() - args.skipRecentHours * 60 * 60 * 1000;
    slicedRepos = slicedRepos.filter((r) => {
      const last = deps.state.getLastSweptAt(r.fullName);
      return !last || new Date(last).getTime() < cutoff;
    });
  }

  let targetRepos = slicedRepos;

  const sweepResults: Array<{
    repo: string;
    owner: string;
    name: string;
    dependabotAlerts: any[];
    codeScanningAlerts: any[];
    issueNumber?: number;
    issueUrl?: string;
  }> = [];

  const [vulnBatch, codeScanMap] = await Promise.all([
    deps.github.getVulnerabilityAlertsBatch(targetRepos),
    (async () => {
      const map: Record<string, any[]> = {};
      await Promise.all(
        targetRepos.map((repo) =>
          deps.readLimit(async () => {
            try {
              map[repo.fullName] = await deps.github.getCodeScanningAlerts(repo.owner, repo.name);
            } catch {
              map[repo.fullName] = [];
            }
          })
        )
      );
      return map;
    })(),
  ]);

  for (const repo of targetRepos) {
    const depAlerts = vulnBatch[repo.fullName] ?? [];
    const codeAlerts = codeScanMap[repo.fullName] ?? [];

    const filteredDep = depAlerts.filter((a) => {
      const idx = severityOrder.indexOf(a.severity);
      return idx >= 0 && idx <= minSevIndex;
    });

    const filteredCode = codeAlerts.filter((a) => {
      const idx = severityOrder.indexOf(a.rule.severity);
      return idx >= 0 && idx <= minSevIndex;
    });

    if (filteredDep.length > 0 || filteredCode.length > 0) {
      sweepResults.push({
        repo: repo.fullName,
        owner: repo.owner,
        name: repo.name,
        dependabotAlerts: filteredDep,
        codeScanningAlerts: filteredCode,
      });
    }
  }

  if (effectiveDryRun) {
    return {
      dryRun: true,
      reposScanned: targetRepos.length,
      reposWithFindings: sweepResults.length,
      findings: sweepResults.map((r) => ({
        repo: r.repo,
        dependabotAlerts: r.dependabotAlerts.length,
        codeScanningAlerts: r.codeScanningAlerts.length,
        vulnerabilities: r.dependabotAlerts.map((a) => ({
          cve: a.cve,
          package: a.package,
          severity: a.severity,
          fixVersion: a.fixVersion,
        })),
      })),
    };
  }

  const jobId = `sweep-${Date.now()}`;
  const workflowTargets: Array<{ owner: string; repo: string; issueNumber: number; vulnerabilities: any[] }> = [];

  await Promise.all(
    sweepResults.map((result) =>
      deps.writeLimit(async () => {
        if (!effectiveSkipRfc) {
          const maxSeverity = result.dependabotAlerts.reduce((max, a) => {
            const idx = severityOrder.indexOf(a.severity);
            const maxIdx = severityOrder.indexOf(max);
            return idx < maxIdx ? a.severity : max;
          }, 'low');

          await Promise.all([
            deps.github.ensureLabel(result.owner, result.name, 'security', 'd73a4a', 'Security vulnerability'),
            deps.github.ensureLabel(result.owner, result.name, 'rfc', '0075ca', 'Request for Change'),
            deps.github.ensureLabel(result.owner, result.name, 'dependencies', '0075ca', 'Dependency updates'),
            deps.github.ensureLabel(result.owner, result.name, 'automated', 'bfd4f2', 'Created by automation'),
            deps.github.ensureLabel(result.owner, result.name, `severity:${maxSeverity}`, maxSeverity === 'critical' ? 'b60205' : maxSeverity === 'high' ? 'ff9800' : 'fbca04', `${maxSeverity} severity`),
          ]);

          const cveTable = result.dependabotAlerts.map((a) =>
            `| ${a.cve || 'N/A'} | ${a.package} | ${a.severity.toUpperCase()} | ${a.currentVersion} | ${a.fixVersion || 'N/A'} |`
          ).join('\n');

          const issueBody = `## RFC: Security Vulnerability Remediation

**Repository:** ${result.repo}
**Severity:** ${maxSeverity.toUpperCase()}
**Date:** ${new Date().toISOString().split('T')[0]}
**Generated by:** git-steer autonomous security sweep

### Vulnerabilities

| CVE | Package | Severity | Current | Fix Version |
|-----|---------|----------|---------|-------------|
${cveTable}

${result.codeScanningAlerts.length > 0 ? `### Code Scanning Alerts

| Rule | Severity | File | Line |
|------|----------|------|------|
${result.codeScanningAlerts.map((a) => `| ${a.rule.id} | ${a.rule.severity} | ${a.location.path} | ${a.location.startLine} |`).join('\n')}
` : ''}
### Change Plan

1. Update vulnerable dependencies to patched versions
2. Run automated tests to verify compatibility
3. Create PR with fixes
4. Merge after review

### Risk Assessment

- **Impact of not fixing:** Potential security breach via known CVEs
- **Impact of fix:** Dependency version bumps, low risk of breakage
- **Rollback plan:** Revert PR if tests fail

---

*This RFC was auto-generated by git-steer. A fix PR will be created automatically.*`;

          const issue = await deps.github.createIssue(result.owner, result.name, {
            title: `[RFC] Security: ${result.dependabotAlerts.length} vulnerabilities (${maxSeverity})`,
            body: issueBody,
            labels: ['security', 'rfc', 'automated', `severity:${maxSeverity}`],
          });

          result.issueNumber = issue.number;
          result.issueUrl = issue.url;

          deps.state.addRfc({
            repo: result.repo,
            issueNumber: issue.number,
            issueUrl: issue.url,
            severity: maxSeverity,
            vulnerabilities: result.dependabotAlerts.map((a) => ({
              cve: a.cve,
              package: a.package,
              severity: a.severity,
              fixVersion: a.fixVersion,
            })),
            status: 'open',
          });
        }

        workflowTargets.push({
          owner: result.owner,
          repo: result.name,
          issueNumber: result.issueNumber || 0,
          vulnerabilities: result.dependabotAlerts,
        });
      })
    )
  );

  if (workflowTargets.length > 0) {
    await deps.github.triggerWorkflow(
      'ry-ops',
      'git-steer',
      'security-sweep.yml',
      'main',
      {
        target_repos: JSON.stringify(workflowTargets),
        severity: minSev,
        job_id: jobId,
        dry_run: 'false',
      }
    );
  }

  const sweepTs = new Date().toISOString();
  for (const r of targetRepos) {
    deps.state.setLastSweptAt(r.fullName, sweepTs);
  }

  const nextIndex = startIndex + chunkSize;
  const hasMore = cursor !== null && nextIndex < allRepos.length;
  if (hasMore && cursor) {
    deps.state.setSweepCursor({ ...cursor, nextIndex });
  } else {
    deps.state.clearSweepCursor();
  }

  return {
    success: true,
    jobId,
    reposScanned: targetRepos.length,
    reposWithFindings: sweepResults.length,
    rfcsCreated: effectiveSkipRfc ? 0 : sweepResults.length,
    workflowDispatched: workflowTargets.length > 0,
    pagination: cursor !== null
      ? {
          chunked: true,
          processedRange: [startIndex, Math.min(nextIndex, allRepos.length) - 1],
          totalRepos: allRepos.length,
          hasMore,
          nextIndex: hasMore ? nextIndex : null,
        }
      : undefined,
    repos: sweepResults.map((r) => ({
      repo: r.repo,
      dependabotAlerts: r.dependabotAlerts.length,
      codeScanningAlerts: r.codeScanningAlerts.length,
      issueNumber: r.issueNumber,
      issueUrl: r.issueUrl,
    })),
  };
}
