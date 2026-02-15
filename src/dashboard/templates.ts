/**
 * Interactive BI Security Dashboard
 *
 * Generates a single static HTML page with embedded JSON data
 * and inline vanilla JS for client-side rendering, filtering,
 * sorting, and search. No external dependencies.
 */

import type { RfcEntry, QualityEntry, SecurityMetrics } from '../state/manager.js';

export interface DashboardData {
  metrics: SecurityMetrics;
  rfcs: RfcEntry[];
  quality: QualityEntry[];
  dateRange?: { start: string; end: string };
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function generateDashboardHtml(data: DashboardData): string {
  const { metrics, rfcs, quality } = data;

  // Flatten vulnerabilities from RFCs into individual rows
  const vulnerabilities = rfcs.flatMap((rfc) =>
    (rfc.vulnerabilities || []).map((v) => ({
      cve: v.cve || 'N/A',
      package: v.package,
      severity: v.severity,
      fixVersion: v.fixVersion || '—',
      repo: rfc.repo,
      status: rfc.status,
      issueNumber: rfc.issueNumber,
      issueUrl: rfc.issueUrl,
      prNumber: rfc.prNumber || null,
      prUrl: rfc.prUrl || null,
    }))
  );

  // Flatten quality findings
  const qualityFindings = quality.flatMap((q) =>
    (q.details || []).map((d) => ({
      file: d.file,
      line: d.line,
      rule: d.rule,
      message: d.message,
      severity: d.severity,
      repo: q.repo,
      tool: q.tool,
    }))
  );

  // Quality summary by tool
  const qualityByTool: Record<string, { runs: number; errors: number; warnings: number }> = {};
  for (const q of quality) {
    if (!qualityByTool[q.tool]) qualityByTool[q.tool] = { runs: 0, errors: 0, warnings: 0 };
    qualityByTool[q.tool].runs++;
    qualityByTool[q.tool].errors += q.errors;
    qualityByTool[q.tool].warnings += q.warnings;
  }

  // Repo data
  const repoNames = Object.keys(metrics.byRepo);
  const cleanRepos = rfcs.length > 0
    ? repoNames.filter((r) => !metrics.byRepo[r] || metrics.byRepo[r].total === 0)
    : [];
  const skippedRepos: string[] = [];

  // Build the embedded DATA object
  const embeddedData = {
    generated: new Date().toISOString(),
    dateRange: data.dateRange || null,
    metrics: {
      totalCves: metrics.totalCves,
      fixedCves: metrics.fixedCves,
      fixRate: metrics.fixRate,
      avgMttr: metrics.avgMttr,
      bySeverity: metrics.bySeverity,
      byRepo: metrics.byRepo,
      timeline: metrics.timeline,
    },
    vulnerabilities,
    rfcs: rfcs.map((r) => ({
      repo: r.repo,
      issueNumber: r.issueNumber,
      issueUrl: r.issueUrl,
      severity: r.severity,
      status: r.status,
      prNumber: r.prNumber || null,
      prUrl: r.prUrl || null,
      vulnCount: (r.vulnerabilities || []).length,
    })),
    quality: quality.map((q) => ({
      repo: q.repo,
      tool: q.tool,
      findings: q.findings,
      errors: q.errors,
      warnings: q.warnings,
      details: q.details || [],
    })),
    qualityFindings,
    qualityByTool,
    repos: {
      total: repoNames.length,
      withAlerts: Object.entries(metrics.byRepo).filter(([, c]) => c.total > 0).length,
      clean: cleanRepos,
      skipped: skippedRepos,
    },
  };

  // Safely serialize data for embedding in script tag
  const dataJson = JSON.stringify(embeddedData)
    .replace(/<\//g, '<\\/')
    .replace(/<!--/g, '<\\!--');

  const openRfcs = rfcs.filter((r) => r.status !== 'fixed' && r.status !== 'closed').length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>git-steer Security Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0d1117;
      color: #e0e0e0;
      padding: 24px;
      min-height: 100vh;
    }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .header {
      text-align: center;
      margin-bottom: 24px;
      border-bottom: 1px solid #30363d;
      padding-bottom: 16px;
    }
    .header h1 { font-size: 24px; margin-bottom: 4px; }
    .header .subtitle { color: #8b949e; font-size: 13px; }

    /* Tab Bar */
    .tab-bar {
      display: flex;
      gap: 0;
      margin-bottom: 24px;
      border-bottom: 2px solid #30363d;
    }
    .tab-btn {
      padding: 10px 20px;
      background: none;
      border: none;
      color: #8b949e;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      margin-bottom: -2px;
      transition: color 0.2s, border-color 0.2s;
    }
    .tab-btn:hover { color: #e0e0e0; }
    .tab-btn.active {
      color: #58a6ff;
      border-bottom-color: #58a6ff;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }

    /* Metric Cards */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .metric-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .metric-card .value {
      font-size: 32px;
      font-weight: bold;
      margin-bottom: 4px;
    }
    .metric-card .label { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
    .green { color: #3fb950; }
    .red { color: #f85149; }
    .yellow { color: #d29922; }
    .blue { color: #58a6ff; }

    /* Filter Pills */
    .filter-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .filter-bar label { color: #8b949e; font-size: 13px; margin-right: 4px; }
    .filter-pill {
      padding: 5px 14px;
      border-radius: 20px;
      border: 1px solid #30363d;
      background: #161b22;
      color: #8b949e;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .filter-pill:hover { border-color: #58a6ff; color: #e0e0e0; }
    .filter-pill.active { border-color: #58a6ff; color: #58a6ff; background: #1c2536; }
    .filter-pill.sev-critical.active { border-color: #f85149; color: #f85149; background: #2d1418; }
    .filter-pill.sev-high.active { border-color: #db6d28; color: #db6d28; background: #2d1f14; }
    .filter-pill.sev-medium.active { border-color: #d29922; color: #d29922; background: #2d2514; }
    .filter-pill.sev-low.active { border-color: #3fb950; color: #3fb950; background: #142d1a; }

    /* Search Bar */
    .search-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
    }
    .search-input {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 8px 12px;
      color: #e0e0e0;
      font-size: 14px;
      width: 320px;
      max-width: 100%;
      outline: none;
      transition: border-color 0.2s;
    }
    .search-input::placeholder { color: #484f58; }
    .search-input:focus { border-color: #58a6ff; }
    .row-count { color: #8b949e; font-size: 13px; margin-left: auto; }

    /* Tables */
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: #161b22;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid #30363d;
    }
    .data-table th {
      padding: 10px 12px;
      text-align: left;
      color: #8b949e;
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: #1c2128;
      border-bottom: 1px solid #30363d;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }
    .data-table th:hover { color: #e0e0e0; }
    .data-table th .sort-arrow { margin-left: 4px; font-size: 10px; }
    .data-table td {
      padding: 8px 12px;
      border-bottom: 1px solid #21262d;
      vertical-align: top;
    }
    .data-table tr:last-child td { border-bottom: none; }
    .data-table tr:hover td { background: #1c2128; }

    /* Severity Pill */
    .severity-pill {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .severity-pill.critical { background: #3d1418; color: #f85149; }
    .severity-pill.high { background: #3d1f14; color: #db6d28; }
    .severity-pill.medium { background: #3d2d14; color: #d29922; }
    .severity-pill.low { background: #143d1a; color: #3fb950; }

    /* Status Badge */
    .status-badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }
    .status-badge.open { background: #3d1418; color: #f85149; }
    .status-badge.in_progress { background: #3d2d14; color: #d29922; }
    .status-badge.fixed { background: #143d1a; color: #3fb950; }
    .status-badge.closed { background: #1c2128; color: #8b949e; }

    /* Charts */
    .charts-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 24px;
    }
    .chart-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
    }
    .chart-card h3 { margin-bottom: 16px; font-size: 14px; color: #8b949e; font-weight: 600; }
    .chart-card svg { display: block; margin: 0 auto; }

    /* Repo Cards */
    .repo-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .repo-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
      cursor: pointer;
      transition: border-color 0.2s;
    }
    .repo-card:hover { border-color: #58a6ff; }
    .repo-card .repo-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .repo-card .repo-name { font-weight: 600; font-size: 14px; }
    .repo-card .repo-count {
      font-size: 12px;
      color: #8b949e;
      background: #1c2128;
      padding: 2px 8px;
      border-radius: 10px;
    }
    .severity-bar {
      display: flex;
      height: 6px;
      border-radius: 3px;
      overflow: hidden;
      background: #21262d;
    }
    .severity-bar .seg { height: 100%; }
    .severity-bar .seg.critical { background: #f85149; }
    .severity-bar .seg.high { background: #db6d28; }
    .severity-bar .seg.medium { background: #d29922; }
    .severity-bar .seg.low { background: #3fb950; }
    .repo-details {
      display: none;
      margin-top: 12px;
      border-top: 1px solid #30363d;
      padding-top: 12px;
    }
    .repo-card.expanded .repo-details { display: block; }

    .clean-repos {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
    }
    .clean-repos summary {
      cursor: pointer;
      color: #8b949e;
      font-size: 13px;
      font-weight: 600;
    }
    .clean-repos .clean-list {
      margin-top: 8px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .clean-repos .clean-tag {
      font-size: 12px;
      background: #143d1a;
      color: #3fb950;
      padding: 2px 10px;
      border-radius: 12px;
    }

    /* Mini table inside repo cards */
    .mini-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    .mini-table th {
      padding: 6px 8px;
      text-align: left;
      color: #8b949e;
      font-weight: 600;
      font-size: 11px;
      border-bottom: 1px solid #30363d;
    }
    .mini-table td {
      padding: 5px 8px;
      border-bottom: 1px solid #21262d;
    }

    /* Top 5 mini table on overview */
    .top-repos-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .top-repos-table th {
      padding: 8px 12px;
      text-align: left;
      color: #8b949e;
      font-weight: 600;
      font-size: 12px;
      border-bottom: 1px solid #30363d;
    }
    .top-repos-table td {
      padding: 6px 12px;
      border-bottom: 1px solid #21262d;
    }
    .top-repos-table .clickable { cursor: pointer; color: #58a6ff; }
    .top-repos-table .clickable:hover { text-decoration: underline; }

    .footer {
      text-align: center;
      color: #484f58;
      font-size: 11px;
      margin-top: 32px;
      padding-top: 16px;
      border-top: 1px solid #21262d;
    }

    /* Subtle card hover */
    .metric-card {
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
    }

    /* ===== Tooltips ===== */
    .metric-card[data-tooltip] {
      position: relative;
      cursor: help;
    }
    .metric-card[data-tooltip]::before,
    .metric-card[data-tooltip]::after {
      position: absolute;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s, transform 0.2s;
    }
    .metric-card[data-tooltip]::after {
      content: attr(data-tooltip);
      bottom: calc(100% + 10px);
      left: 50%;
      transform: translateX(-50%) translateY(4px);
      background: #1c2128;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 8px 12px;
      font-size: 12px;
      color: #8b949e;
      white-space: normal;
      width: 240px;
      text-align: center;
      line-height: 1.4;
      z-index: 100;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    }
    .metric-card[data-tooltip]::before {
      content: '';
      bottom: calc(100% + 4px);
      left: 50%;
      transform: translateX(-50%);
      border: 6px solid transparent;
      border-top-color: #30363d;
      z-index: 101;
    }
    .metric-card[data-tooltip]:hover::before,
    .metric-card[data-tooltip]:hover::after {
      opacity: 1;
    }
    .metric-card[data-tooltip]:hover::after {
      transform: translateX(-50%) translateY(0);
    }

    /* ===== Action Bar ===== */
    .action-bar {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    .action-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 16px;
      border-radius: 6px;
      border: 1px solid #30363d;
      background: #161b22;
      color: #e0e0e0;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }
    .action-btn:hover { border-color: #58a6ff; color: #58a6ff; }
    .action-btn.primary {
      background: #238636;
      border-color: #2ea043;
      color: #fff;
    }
    .action-btn.primary:hover {
      background: #2ea043;
      border-color: #3fb950;
    }
    .action-btn svg { width: 14px; height: 14px; fill: currentColor; }
    .last-scanned {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: #8b949e;
      font-size: 12px;
    }
    .pulse-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: #3fb950;
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(63,185,80,0.4); }
      50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(63,185,80,0); }
    }

    /* ===== Modal ===== */
    .modal-overlay {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.6);
      backdrop-filter: blur(4px);
      z-index: 200;
      align-items: center;
      justify-content: center;
    }
    .modal-overlay.active { display: flex; }
    .modal {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 24px;
      width: 420px;
      max-width: 90vw;
      box-shadow: 0 16px 48px rgba(0,0,0,0.5);
    }
    .modal h3 { font-size: 16px; margin-bottom: 4px; }
    .modal p { color: #8b949e; font-size: 13px; margin-bottom: 16px; line-height: 1.5; }
    .modal-input {
      width: 100%;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 8px 12px;
      color: #e0e0e0;
      font-size: 13px;
      font-family: monospace;
      outline: none;
      margin-bottom: 12px;
    }
    .modal-input:focus { border-color: #58a6ff; }
    .modal-actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
    }
    .modal-feedback {
      font-size: 12px;
      margin-top: 8px;
      min-height: 18px;
    }

    /* ===== Toast ===== */
    .toast-container {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 300;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .toast {
      background: #1c2128;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 10px 16px;
      font-size: 13px;
      color: #e0e0e0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
      animation: toastIn 0.3s ease-out;
    }
    .toast.success { border-color: #3fb950; color: #3fb950; }
    .toast.error { border-color: #f85149; color: #f85149; }
    @keyframes toastIn {
      from { transform: translateY(10px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* ===== Keyboard Hints ===== */
    .kb-hint-btn {
      position: fixed;
      bottom: 16px;
      left: 16px;
      width: 32px; height: 32px;
      border-radius: 50%;
      background: #161b22;
      border: 1px solid #30363d;
      color: #8b949e;
      font-size: 14px;
      font-weight: bold;
      cursor: pointer;
      z-index: 50;
      transition: all 0.2s;
    }
    .kb-hint-btn:hover { border-color: #58a6ff; color: #58a6ff; }
    .kb-hints {
      display: none;
      position: fixed;
      bottom: 56px;
      left: 16px;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 12px;
      color: #8b949e;
      z-index: 50;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    }
    .kb-hints.active { display: block; }
    .kb-hints kbd {
      display: inline-block;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 3px;
      padding: 1px 6px;
      font-size: 11px;
      font-family: monospace;
      margin-right: 6px;
    }
    .kb-hints div { margin-bottom: 4px; }
    .kb-hints div:last-child { margin-bottom: 0; }

    /* ===== Fullscreen ===== */
    .fullscreen-btn {
      background: none;
      border: none;
      color: #8b949e;
      cursor: pointer;
      padding: 4px;
      transition: color 0.2s;
    }
    .fullscreen-btn:hover { color: #e0e0e0; }
    .fullscreen-btn svg { width: 16px; height: 16px; fill: currentColor; }

    /* ===== Click-to-copy ===== */
    .copyable { cursor: pointer; position: relative; }
    .copyable:hover { text-decoration: underline; }
    .copy-flash {
      position: absolute;
      top: -24px;
      left: 50%;
      transform: translateX(-50%);
      background: #1c2128;
      border: 1px solid #3fb950;
      color: #3fb950;
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 4px;
      white-space: nowrap;
      animation: toastIn 0.2s ease-out;
      pointer-events: none;
    }

    /* ===== About Tab ===== */
    .about-content {
      max-width: 720px;
      margin: 0 auto;
      line-height: 1.7;
      font-size: 14px;
    }
    .about-content h2 {
      font-size: 20px;
      margin: 28px 0 12px 0;
      color: #e0e0e0;
      border-bottom: 1px solid #21262d;
      padding-bottom: 8px;
    }
    .about-content h2:first-child { margin-top: 0; }
    .about-content p { color: #8b949e; margin-bottom: 12px; }
    .about-content ul { color: #8b949e; margin: 0 0 12px 20px; }
    .about-content li { margin-bottom: 6px; }
    .about-content code {
      background: #1c2128;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      color: #e0e0e0;
    }
    .about-content kbd {
      display: inline-block;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 3px;
      padding: 1px 6px;
      font-size: 11px;
      font-family: monospace;
    }
    .about-content .metric-explainer {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 8px 16px;
      margin: 12px 0;
      font-size: 13px;
    }
    .about-content .metric-explainer dt {
      font-weight: 600;
      color: #e0e0e0;
    }
    .about-content .metric-explainer dd {
      color: #8b949e;
      margin: 0;
    }

    /* Responsive */
    @media (max-width: 768px) {
      body { padding: 12px; }
      .charts-row { grid-template-columns: 1fr; }
      .repo-grid { grid-template-columns: 1fr; }
      .search-input { width: 100%; }
      .filter-bar { gap: 6px; }
      .tab-btn { padding: 8px 12px; font-size: 13px; }
      .data-table { font-size: 12px; }
      .data-table th, .data-table td { padding: 6px 8px; }
      .metrics-grid { grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
      .metric-card .value { font-size: 24px; }
      .action-bar { gap: 6px; }
      .action-btn { padding: 6px 10px; font-size: 11px; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>git-steer Security Dashboard <button class="fullscreen-btn" id="fullscreen-btn" title="Toggle fullscreen"><svg viewBox="0 0 16 16"><path d="M1.5 1a.5.5 0 0 0-.5.5v4a.5.5 0 0 1-1 0v-4A1.5 1.5 0 0 1 1.5 0h4a.5.5 0 0 1 0 1h-4zM10 .5a.5.5 0 0 1 .5-.5h4A1.5 1.5 0 0 1 16 1.5v4a.5.5 0 0 1-1 0v-4a.5.5 0 0 0-.5-.5h-4a.5.5 0 0 1-.5-.5zM.5 10a.5.5 0 0 1 .5.5v4a.5.5 0 0 0 .5.5h4a.5.5 0 0 1 0 1h-4A1.5 1.5 0 0 1 0 14.5v-4a.5.5 0 0 1 .5-.5zm15 0a.5.5 0 0 1 .5.5v4a1.5 1.5 0 0 1-1.5 1.5h-4a.5.5 0 0 1 0-1h4a.5.5 0 0 0 .5-.5v-4a.5.5 0 0 1 .5-.5z"/></svg></button></h1>
    <div class="subtitle" id="subtitle"></div>
    <div class="action-bar">
      <span class="last-scanned"><span class="pulse-dot"></span> <span id="time-ago"></span></span>
      <button class="action-btn primary" id="btn-run-scan"><svg viewBox="0 0 16 16"><path d="M11.251.068a.5.5 0 0 1 .227.58L9.677 6.5H13a.5.5 0 0 1 .364.843l-8 8.5a.5.5 0 0 1-.842-.49L6.323 9.5H3a.5.5 0 0 1-.364-.843l8-8.5a.5.5 0 0 1 .615-.09z"/></svg> Run Security Scan</button>
      <button class="action-btn" id="btn-copy-cmd"><svg viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z"/></svg> Copy Command</button>
      <button class="action-btn" id="btn-export-csv"><svg viewBox="0 0 16 16"><path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/></svg> Export CSV</button>
    </div>
  </div>

  <!-- Modal for PAT token -->
  <div class="modal-overlay" id="scan-modal">
    <div class="modal">
      <h3>Run Security Scan</h3>
      <p>Enter a GitHub Personal Access Token with <code>repo</code> and <code>actions:write</code> scopes to trigger a workflow dispatch. The token is stored only in your browser session.</p>
      <input class="modal-input" id="pat-input" type="password" placeholder="ghp_xxxxxxxxxxxxxxxxxxxx">
      <div class="modal-actions">
        <button class="action-btn" id="modal-cancel">Cancel</button>
        <button class="action-btn primary" id="modal-trigger">Trigger Scan</button>
      </div>
      <div class="modal-feedback" id="modal-feedback"></div>
    </div>
  </div>

  <!-- Toast container -->
  <div class="toast-container" id="toast-container"></div>

  <!-- Keyboard hints -->
  <button class="kb-hint-btn" id="kb-hint-btn" title="Keyboard shortcuts">?</button>
  <div class="kb-hints" id="kb-hints">
    <div><kbd>1</kbd>-<kbd>5</kbd> Switch tabs</div>
    <div><kbd>Esc</kbd> Close modal</div>
    <div><kbd>?</kbd> Toggle this panel</div>
  </div>

  <div class="tab-bar">
    <button class="tab-btn active" data-tab="overview">Overview</button>
    <button class="tab-btn" data-tab="cve-details">CVE Details</button>
    <button class="tab-btn" data-tab="repositories">Repositories</button>
    <button class="tab-btn" data-tab="code-quality">Code Quality</button>
    <button class="tab-btn" data-tab="about">About</button>
  </div>

  <!-- Tab 1: Overview -->
  <div class="tab-content active" id="tab-overview">
    <div class="metrics-grid" id="metrics-grid"></div>
    <div class="filter-bar" id="overview-filters">
      <label>Severity:</label>
    </div>
    <div class="charts-row">
      <div class="chart-card">
        <h3>Vulnerabilities by Severity</h3>
        <div id="donut-chart"></div>
      </div>
      <div class="chart-card">
        <h3>CVEs Over Time</h3>
        <div id="timeline-chart"></div>
      </div>
    </div>
    <div class="chart-card" style="margin-bottom:24px">
      <h3>Top Riskiest Repositories</h3>
      <div id="top-repos"></div>
    </div>
  </div>

  <!-- Tab 2: CVE Details -->
  <div class="tab-content" id="tab-cve-details">
    <div class="search-bar">
      <input class="search-input" id="cve-search" type="text" placeholder="Search CVE ID, package, or repo...">
      <span class="row-count" id="cve-row-count"></span>
    </div>
    <div class="filter-bar" id="cve-filters">
      <label>Severity:</label>
    </div>
    <div style="overflow-x:auto">
      <table class="data-table" id="cve-table">
        <thead>
          <tr>
            <th data-col="cve">CVE ID <span class="sort-arrow"></span></th>
            <th data-col="package">Package <span class="sort-arrow"></span></th>
            <th data-col="severity">Severity <span class="sort-arrow"></span></th>
            <th data-col="fixVersion">Fix Version <span class="sort-arrow"></span></th>
            <th data-col="repo">Repository <span class="sort-arrow"></span></th>
            <th data-col="status">Status <span class="sort-arrow"></span></th>
            <th data-col="issueNumber">RFC # <span class="sort-arrow"></span></th>
          </tr>
        </thead>
        <tbody id="cve-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 3: Repositories -->
  <div class="tab-content" id="tab-repositories">
    <div class="filter-bar" id="repo-filters">
      <label>Severity:</label>
    </div>
    <div class="repo-grid" id="repo-grid"></div>
    <div id="clean-repos-section"></div>
  </div>

  <!-- Tab 4: Code Quality -->
  <div class="tab-content" id="tab-code-quality">
    <div class="metrics-grid" id="quality-metrics"></div>
    <div class="search-bar">
      <input class="search-input" id="quality-search" type="text" placeholder="Search file, rule, or message...">
      <span class="row-count" id="quality-row-count"></span>
    </div>
    <div style="overflow-x:auto">
      <table class="data-table" id="quality-table">
        <thead>
          <tr>
            <th data-col="file">File <span class="sort-arrow"></span></th>
            <th data-col="line">Line <span class="sort-arrow"></span></th>
            <th data-col="rule">Rule <span class="sort-arrow"></span></th>
            <th data-col="message">Message <span class="sort-arrow"></span></th>
            <th data-col="severity">Severity <span class="sort-arrow"></span></th>
            <th data-col="repo">Repo <span class="sort-arrow"></span></th>
            <th data-col="tool">Tool <span class="sort-arrow"></span></th>
          </tr>
        </thead>
        <tbody id="quality-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 5: About -->
  <div class="tab-content" id="tab-about">
    <div class="about-content">
      <h2>What is git-steer?</h2>
      <p><a href="https://github.com/ry-ops/git-steer">git-steer</a> is a self-hosting GitHub autonomy engine that provides 100% autonomous control over your GitHub account through a Model Context Protocol (MCP) server. It scans repositories for security vulnerabilities, tracks remediation via RFC issues, and generates this dashboard automatically.</p>
      <p>This dashboard is regenerated daily by a GitHub Actions workflow and deployed to GitHub Pages. No local machine required.</p>

      <h2>Reading the Metrics</h2>
      <dl class="metric-explainer">
        <dt>Total CVEs</dt>
        <dd>Total Common Vulnerabilities and Exposures detected across all scanned repositories.</dd>
        <dt>Fixed</dt>
        <dd>Number of CVEs that have been remediated with patches or dependency updates.</dd>
        <dt>Fix Rate</dt>
        <dd>Percentage of detected CVEs resolved. <span class="green">Green &ge;80%</span>, <span class="yellow">Yellow &ge;50%</span>, <span class="red">Red &lt;50%</span>.</dd>
        <dt>Avg MTTR</dt>
        <dd>Mean Time To Resolution &mdash; average hours from CVE detection to fix. <span class="green">Green &le;24h</span>, <span class="yellow">Yellow &le;48h</span>, <span class="red">Red &gt;48h</span>.</dd>
        <dt>Open RFCs</dt>
        <dd>Active Request for Change issues tracking vulnerability remediation in progress.</dd>
        <dt>Total Runs</dt>
        <dd>Number of code quality tool executions (e.g. CodeQL scans) across repositories.</dd>
        <dt>Total Errors</dt>
        <dd>Code quality issues classified as errors requiring immediate attention.</dd>
        <dt>Total Warnings</dt>
        <dd>Code quality issues classified as warnings for review.</dd>
      </dl>

      <h2>Dashboard Features</h2>
      <ul>
        <li><strong>5 interactive tabs</strong>: Overview, CVE Details, Repositories, Code Quality, and this About page</li>
        <li><strong>Global severity filter</strong>: Click CRITICAL / HIGH / MEDIUM / LOW to filter across all tabs</li>
        <li><strong>Sortable tables</strong>: Click any column header to sort ascending/descending</li>
        <li><strong>Live search</strong>: Type to filter CVE and quality tables in real time</li>
        <li><strong>Expandable repo cards</strong>: Click to drill into per-repo vulnerability details</li>
        <li><strong>Hover tooltips</strong>: Hover over metric cards for descriptions</li>
        <li><strong>Click-to-copy CVE IDs</strong>: Click any CVE link to copy the ID to clipboard</li>
        <li><strong>CSV export</strong>: Download the current tab's data as a CSV file</li>
        <li><strong>NVD links</strong>: Every CVE ID links directly to the NVD detail page</li>
      </ul>

      <h2>Keyboard Shortcuts</h2>
      <ul>
        <li><kbd>1</kbd> &ndash; <kbd>5</kbd> &mdash; Switch between tabs</li>
        <li><kbd>Esc</kbd> &mdash; Close any open modal or panel</li>
        <li><kbd>?</kbd> &mdash; Toggle keyboard shortcuts hint</li>
      </ul>

      <h2>Automation</h2>
      <p>This dashboard is automatically refreshed daily at 6:00 AM UTC by the <code>Heartbeat</code> GitHub Actions workflow. The workflow scans all managed repositories for Dependabot alerts, regenerates the dashboard HTML, and deploys it to GitHub Pages.</p>
      <p>You can also trigger a manual refresh using the <strong>Run Security Scan</strong> button in the header, which dispatches the workflow on demand.</p>

      <h2>Links</h2>
      <ul>
        <li><a href="https://github.com/ry-ops/git-steer" target="_blank" rel="noopener">git-steer on GitHub</a></li>
        <li><a href="https://github.com/ry-ops/git-steer/actions/workflows/heartbeat.yml" target="_blank" rel="noopener">Heartbeat Workflow (daily scans)</a></li>
        <li><a href="https://github.com/ry-ops/git-steer-state" target="_blank" rel="noopener">State Repository</a></li>
      </ul>
    </div>
  </div>

  <div class="footer">
    Powered by <a href="https://github.com/ry-ops/git-steer">git-steer</a> &middot; Open RFCs: ${openRfcs}
  </div>

  <script>
  const DATA = ${dataJson};

  // ===== Utility =====
  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ===== Tab Switching =====
  document.querySelectorAll('.tab-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // ===== Global Severity Filter State =====
  var activeSeverity = 'all';

  function setSeverity(sev) {
    activeSeverity = sev;
    document.querySelectorAll('.filter-pill').forEach(function(p) {
      p.classList.toggle('active', p.dataset.sev === sev);
    });
    renderCveTable();
    renderRepoGrid();
    renderQualityTable();
  }

  function buildFilterPills(container) {
    var sevs = ['all','critical','high','medium','low'];
    sevs.forEach(function(s) {
      var btn = document.createElement('button');
      btn.className = 'filter-pill' + (s !== 'all' ? ' sev-' + s : '') + (s === 'all' ? ' active' : '');
      btn.textContent = s === 'all' ? 'ALL' : s.toUpperCase();
      btn.dataset.sev = s;
      btn.addEventListener('click', function() { setSeverity(s); });
      container.appendChild(btn);
    });
  }

  // ===== Subtitle =====
  (function() {
    var dr = DATA.dateRange ? (DATA.dateRange.start + ' to ' + DATA.dateRange.end) : 'All time';
    var gen = DATA.generated.split('T')[0];
    document.getElementById('subtitle').textContent = 'Period: ' + dr + ' \\u00b7 Generated: ' + gen;
  })();

  // ===== Metrics Cards =====
  (function() {
    var m = DATA.metrics;
    var fixPct = Math.round(m.fixRate * 100);
    var mttr = Math.round(m.avgMttr);
    var openRfcs = DATA.rfcs.filter(function(r) { return r.status !== 'fixed' && r.status !== 'closed'; }).length;
    var cards = [
      { value: m.totalCves, label: 'Total CVEs', cls: '', tooltip: 'Total Common Vulnerabilities and Exposures detected across all scanned repositories' },
      { value: m.fixedCves, label: 'Fixed', cls: 'green', tooltip: 'Number of CVEs that have been remediated with patches or updates' },
      { value: fixPct + '%', label: 'Fix Rate', cls: fixPct >= 80 ? 'green' : fixPct >= 50 ? 'yellow' : 'red', tooltip: 'Percentage of detected CVEs that have been resolved. Green \\u226580%, Yellow \\u226550%, Red <50%' },
      { value: mttr + 'h', label: 'Avg MTTR', cls: mttr <= 24 ? 'green' : mttr <= 48 ? 'yellow' : 'red', tooltip: 'Mean Time To Resolution \\u2014 average hours from CVE detection to fix. Green \\u226424h, Yellow \\u226448h, Red >48h' },
      { value: openRfcs, label: 'Open RFCs', cls: 'blue', tooltip: 'Active Request for Change issues tracking vulnerability remediation in progress' },
    ];
    var grid = document.getElementById('metrics-grid');
    cards.forEach(function(c) {
      var div = document.createElement('div');
      div.className = 'metric-card';
      if (c.tooltip) div.setAttribute('data-tooltip', c.tooltip);
      div.innerHTML = '<div class="value ' + c.cls + '">' + esc(String(c.value)) + '</div><div class="label">' + esc(c.label) + '</div>';
      grid.appendChild(div);
    });
  })();

  // ===== Filter Pills on each tab =====
  buildFilterPills(document.getElementById('overview-filters'));
  buildFilterPills(document.getElementById('cve-filters'));
  buildFilterPills(document.getElementById('repo-filters'));

  // ===== Donut Chart =====
  (function() {
    var sev = DATA.metrics.bySeverity;
    var keys = Object.keys(sev);
    var total = keys.reduce(function(s, k) { return s + sev[k].total; }, 0);
    if (total === 0) {
      document.getElementById('donut-chart').innerHTML = '<p style="color:#8b949e;text-align:center;padding:40px 0">No vulnerability data</p>';
      return;
    }
    var colors = { critical: '#f85149', high: '#db6d28', medium: '#d29922', low: '#3fb950' };
    var cx = 120, cy = 120, r = 90, ir = 55;
    var svg = '<svg width="320" height="260" viewBox="0 0 320 260" xmlns="http://www.w3.org/2000/svg">';
    var angle = -Math.PI / 2;
    keys.forEach(function(k) {
      var pct = sev[k].total / total;
      if (pct === 0) return;
      var a1 = angle;
      var a2 = angle + pct * 2 * Math.PI;
      var large = pct > 0.5 ? 1 : 0;
      var x1o = cx + r * Math.cos(a1), y1o = cy + r * Math.sin(a1);
      var x2o = cx + r * Math.cos(a2), y2o = cy + r * Math.sin(a2);
      var x1i = cx + ir * Math.cos(a2), y1i = cy + ir * Math.sin(a2);
      var x2i = cx + ir * Math.cos(a1), y2i = cy + ir * Math.sin(a1);
      svg += '<path d="M ' + x1o + ' ' + y1o + ' A ' + r + ' ' + r + ' 0 ' + large + ' 1 ' + x2o + ' ' + y2o +
             ' L ' + x1i + ' ' + y1i + ' A ' + ir + ' ' + ir + ' 0 ' + large + ' 0 ' + x2i + ' ' + y2i +
             ' Z" fill="' + (colors[k] || '#58a6ff') + '">' +
             '<title>' + k.toUpperCase() + ': ' + sev[k].total + ' (' + Math.round(pct * 100) + '%)</title></path>';
      angle = a2;
    });
    svg += '<text x="' + cx + '" y="' + (cy - 6) + '" text-anchor="middle" font-size="24" font-weight="bold" fill="#e0e0e0">' + total + '</text>';
    svg += '<text x="' + cx + '" y="' + (cy + 14) + '" text-anchor="middle" font-size="11" fill="#8b949e">Total</text>';
    // Legend
    var ly = 10;
    keys.forEach(function(k) {
      svg += '<rect x="260" y="' + ly + '" width="10" height="10" rx="2" fill="' + (colors[k] || '#58a6ff') + '"/>';
      svg += '<text x="275" y="' + (ly + 9) + '" font-size="11" fill="#8b949e">' + k.charAt(0).toUpperCase() + k.slice(1) + ' (' + sev[k].total + ')</text>';
      ly += 20;
    });
    svg += '</svg>';
    document.getElementById('donut-chart').innerHTML = svg;
  })();

  // ===== Timeline Chart =====
  (function() {
    var tl = DATA.metrics.timeline;
    if (tl.length === 0) {
      document.getElementById('timeline-chart').innerHTML = '<p style="color:#8b949e;text-align:center;padding:40px 0">No timeline data</p>';
      return;
    }
    var w = 500, h = 240;
    var pad = { top: 30, right: 70, bottom: 50, left: 40 };
    var cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    var allVals = tl.map(function(t) { return Math.max(t.opened, t.fixed); });
    var maxV = Math.max.apply(null, allVals.concat([1]));
    var stepX = tl.length > 1 ? cw / (tl.length - 1) : 0;

    function buildLine(vals, color, dashed) {
      var pts = vals.map(function(v, i) {
        var x = pad.left + stepX * i;
        var y = pad.top + ch - (v / maxV) * ch;
        return (i === 0 ? 'M' : 'L') + ' ' + x + ' ' + y;
      }).join(' ');
      return '<path d="' + pts + '" fill="none" stroke="' + color + '" stroke-width="2"' + (dashed ? ' stroke-dasharray="4"' : '') + '/>';
    }

    var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
    // Grid
    for (var i = 0; i <= 4; i++) {
      var yy = pad.top + ch - (i / 4) * ch;
      var val = Math.round((maxV / 4) * i);
      svg += '<line x1="' + pad.left + '" y1="' + yy + '" x2="' + (pad.left + cw) + '" y2="' + yy + '" stroke="#21262d" stroke-dasharray="2"/>';
      svg += '<text x="' + (pad.left - 5) + '" y="' + (yy + 4) + '" text-anchor="end" font-size="10" fill="#484f58">' + val + '</text>';
    }
    svg += buildLine(tl.map(function(t) { return t.opened; }), '#f85149', false);
    svg += buildLine(tl.map(function(t) { return t.fixed; }), '#3fb950', true);
    // Dots with tooltips
    tl.forEach(function(t, i) {
      var x = pad.left + stepX * i;
      var yo = pad.top + ch - (t.opened / maxV) * ch;
      var yf = pad.top + ch - (t.fixed / maxV) * ch;
      svg += '<circle cx="' + x + '" cy="' + yo + '" r="3" fill="#f85149"><title>' + t.date + ': ' + t.opened + ' opened</title></circle>';
      svg += '<circle cx="' + x + '" cy="' + yf + '" r="3" fill="#3fb950"><title>' + t.date + ': ' + t.fixed + ' fixed</title></circle>';
    });
    // X labels
    var interval = Math.max(1, Math.floor(tl.length / 6));
    tl.forEach(function(t, i) {
      if (i % interval !== 0 && i !== tl.length - 1) return;
      var x = pad.left + stepX * i;
      svg += '<text x="' + x + '" y="' + (h - pad.bottom + 14) + '" text-anchor="middle" font-size="9" fill="#484f58" transform="rotate(-35,' + x + ',' + (h - pad.bottom + 14) + ')">' + t.date + '</text>';
    });
    // Legend
    svg += '<rect x="' + (w - 65) + '" y="' + pad.top + '" width="8" height="8" fill="#f85149" rx="1"/>';
    svg += '<text x="' + (w - 53) + '" y="' + (pad.top + 8) + '" font-size="10" fill="#8b949e">Opened</text>';
    svg += '<rect x="' + (w - 65) + '" y="' + (pad.top + 16) + '" width="8" height="8" fill="#3fb950" rx="1"/>';
    svg += '<text x="' + (w - 53) + '" y="' + (pad.top + 24) + '" font-size="10" fill="#8b949e">Fixed</text>';
    svg += '</svg>';
    document.getElementById('timeline-chart').innerHTML = svg;
  })();

  // ===== Top 5 Riskiest Repos =====
  (function() {
    var byRepo = DATA.metrics.byRepo;
    var entries = Object.keys(byRepo).map(function(r) {
      return { repo: r, total: byRepo[r].total, fixed: byRepo[r].fixed, open: byRepo[r].total - byRepo[r].fixed };
    }).sort(function(a, b) { return b.open - a.open; }).slice(0, 5);

    if (entries.length === 0) {
      document.getElementById('top-repos').innerHTML = '<p style="color:#8b949e;text-align:center;padding:20px 0">No repository data</p>';
      return;
    }
    var html = '<table class="top-repos-table"><tr><th>Repository</th><th>Open</th><th>Fixed</th><th>Total</th></tr>';
    entries.forEach(function(e) {
      html += '<tr><td class="clickable" onclick="switchToRepoTab(\\'' + esc(e.repo).replace(/'/g, "\\\\'") + '\\')">' + esc(e.repo) + '</td>';
      html += '<td><span class="' + (e.open > 0 ? 'red' : '') + '">' + e.open + '</span></td>';
      html += '<td class="green">' + e.fixed + '</td>';
      html += '<td>' + e.total + '</td></tr>';
    });
    html += '</table>';
    document.getElementById('top-repos').innerHTML = html;
  })();

  function switchToRepoTab(repo) {
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
    document.querySelector('[data-tab="repositories"]').classList.add('active');
    document.getElementById('tab-repositories').classList.add('active');
    // Expand the repo card
    setTimeout(function() {
      var cards = document.querySelectorAll('.repo-card');
      cards.forEach(function(card) {
        if (card.dataset.repo === repo) {
          card.classList.add('expanded');
          card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      });
    }, 50);
  }

  // ===== CVE Details Table =====
  var cveSortCol = null, cveSortAsc = true;

  function renderCveTable() {
    var vulns = DATA.vulnerabilities.slice();
    var search = (document.getElementById('cve-search').value || '').toLowerCase();

    // Severity filter
    if (activeSeverity !== 'all') {
      vulns = vulns.filter(function(v) { return v.severity === activeSeverity; });
    }
    // Search filter
    if (search) {
      vulns = vulns.filter(function(v) {
        return (v.cve + ' ' + v.package + ' ' + v.repo + ' ' + v.status).toLowerCase().indexOf(search) !== -1;
      });
    }
    // Sort
    if (cveSortCol) {
      vulns.sort(function(a, b) {
        var va = a[cveSortCol], vb = b[cveSortCol];
        if (va == null) va = '';
        if (vb == null) vb = '';
        if (typeof va === 'number' && typeof vb === 'number') return cveSortAsc ? va - vb : vb - va;
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        return cveSortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      });
    }

    var totalVulns = DATA.vulnerabilities.length;
    var filtered = activeSeverity !== 'all' ? DATA.vulnerabilities.filter(function(v) { return v.severity === activeSeverity; }).length : totalVulns;
    document.getElementById('cve-row-count').textContent = 'Showing ' + vulns.length + ' of ' + filtered + ' vulnerabilities';

    var tbody = document.getElementById('cve-tbody');
    var rows = '';
    vulns.forEach(function(v) {
      var cveLink = v.cve !== 'N/A' ? '<a href="https://nvd.nist.gov/vuln/detail/' + esc(v.cve) + '" target="_blank" rel="noopener">' + esc(v.cve) + '</a>' : 'N/A';
      var sevPill = '<span class="severity-pill ' + esc(v.severity) + '">' + esc(v.severity) + '</span>';
      var statusBadge = '<span class="status-badge ' + esc(v.status) + '">' + esc(v.status.replace('_', ' ')) + '</span>';
      var rfcLink = v.issueUrl ? '<a href="' + esc(v.issueUrl) + '" target="_blank" rel="noopener">#' + v.issueNumber + '</a>' : '#' + v.issueNumber;
      rows += '<tr>';
      rows += '<td>' + cveLink + '</td>';
      rows += '<td>' + esc(v.package) + '</td>';
      rows += '<td>' + sevPill + '</td>';
      rows += '<td>' + esc(v.fixVersion) + '</td>';
      rows += '<td>' + esc(v.repo) + '</td>';
      rows += '<td>' + statusBadge + '</td>';
      rows += '<td>' + rfcLink + '</td>';
      rows += '</tr>';
    });
    tbody.innerHTML = rows;

    // Update sort arrows
    document.querySelectorAll('#cve-table th').forEach(function(th) {
      var arrow = th.querySelector('.sort-arrow');
      if (th.dataset.col === cveSortCol) {
        arrow.innerHTML = cveSortAsc ? '&#9650;' : '&#9660;';
      } else {
        arrow.innerHTML = '';
      }
    });
  }

  document.querySelectorAll('#cve-table th').forEach(function(th) {
    th.addEventListener('click', function() {
      var col = th.dataset.col;
      if (cveSortCol === col) {
        cveSortAsc = !cveSortAsc;
      } else {
        cveSortCol = col;
        cveSortAsc = true;
      }
      renderCveTable();
    });
  });

  document.getElementById('cve-search').addEventListener('input', renderCveTable);
  renderCveTable();

  // ===== Repositories Tab =====
  function renderRepoGrid() {
    var byRepo = DATA.metrics.byRepo;
    var repos = Object.keys(byRepo).filter(function(r) { return byRepo[r].total > 0; });
    // Sort by open desc
    repos.sort(function(a, b) { return (byRepo[b].total - byRepo[b].fixed) - (byRepo[a].total - byRepo[a].fixed); });

    var container = document.getElementById('repo-grid');
    container.innerHTML = '';

    repos.forEach(function(repo) {
      var repoVulns = DATA.vulnerabilities.filter(function(v) { return v.repo === repo; });
      // Severity filter
      if (activeSeverity !== 'all') {
        repoVulns = repoVulns.filter(function(v) { return v.severity === activeSeverity; });
      }

      var counts = { critical: 0, high: 0, medium: 0, low: 0 };
      repoVulns.forEach(function(v) { if (counts[v.severity] !== undefined) counts[v.severity]++; });
      var total = repoVulns.length;

      if (activeSeverity !== 'all' && total === 0) return;

      var card = document.createElement('div');
      card.className = 'repo-card';
      card.dataset.repo = repo;

      // Severity bar segments
      var barHtml = '<div class="severity-bar">';
      if (total > 0) {
        ['critical','high','medium','low'].forEach(function(s) {
          if (counts[s] > 0) {
            barHtml += '<div class="seg ' + s + '" style="width:' + (counts[s] / total * 100) + '%"></div>';
          }
        });
      }
      barHtml += '</div>';

      // Mini CVE table
      var miniTable = '<table class="mini-table"><tr><th>CVE</th><th>Package</th><th>Severity</th><th>Status</th></tr>';
      repoVulns.forEach(function(v) {
        var cveLink = v.cve !== 'N/A' ? '<a href="https://nvd.nist.gov/vuln/detail/' + esc(v.cve) + '" target="_blank" rel="noopener">' + esc(v.cve) + '</a>' : 'N/A';
        miniTable += '<tr><td>' + cveLink + '</td><td>' + esc(v.package) + '</td>';
        miniTable += '<td><span class="severity-pill ' + esc(v.severity) + '">' + esc(v.severity) + '</span></td>';
        miniTable += '<td><span class="status-badge ' + esc(v.status) + '">' + esc(v.status.replace('_',' ')) + '</span></td></tr>';
      });
      miniTable += '</table>';

      var repoUrl = 'https://github.com/' + esc(repo);
      card.innerHTML = '<div class="repo-header"><span class="repo-name"><a href="' + repoUrl + '" target="_blank" rel="noopener">' + esc(repo) + '</a></span>' +
        '<span class="repo-count">' + total + ' alert' + (total !== 1 ? 's' : '') + '</span></div>' +
        barHtml +
        '<div class="repo-details">' + miniTable + '</div>';

      card.addEventListener('click', function(e) {
        if (e.target.tagName === 'A') return;
        card.classList.toggle('expanded');
      });

      container.appendChild(card);
    });

    // Clean repos
    var cleanSection = document.getElementById('clean-repos-section');
    var cleanRepos = DATA.repos.clean || [];
    // Also add repos with 0 alerts that aren't in byRepo
    var reposWithAlerts = new Set(Object.keys(byRepo).filter(function(r) { return byRepo[r].total > 0; }));
    var allClean = cleanRepos.filter(function(r) { return !reposWithAlerts.has(r); });

    if (allClean.length > 0) {
      var html = '<div class="clean-repos"><details><summary>' + allClean.length + ' clean repositories (0 findings)</summary><div class="clean-list">';
      allClean.forEach(function(r) { html += '<span class="clean-tag">' + esc(r) + '</span>'; });
      html += '</div></details></div>';
      cleanSection.innerHTML = html;
    } else {
      cleanSection.innerHTML = '';
    }
  }
  renderRepoGrid();

  // ===== Code Quality Tab =====
  (function() {
    var bt = DATA.qualityByTool;
    var tools = Object.keys(bt);
    var totalRuns = tools.reduce(function(s, t) { return s + bt[t].runs; }, 0);
    var totalErrors = tools.reduce(function(s, t) { return s + bt[t].errors; }, 0);
    var totalWarnings = tools.reduce(function(s, t) { return s + bt[t].warnings; }, 0);

    var grid = document.getElementById('quality-metrics');
    var cards = [
      { value: totalRuns, label: 'Total Runs', cls: 'blue', tooltip: 'Number of code quality tool executions (e.g. CodeQL scans) across all repositories' },
      { value: totalErrors, label: 'Total Errors', cls: totalErrors > 0 ? 'red' : 'green', tooltip: 'Code quality issues classified as errors requiring attention' },
      { value: totalWarnings, label: 'Total Warnings', cls: totalWarnings > 0 ? 'yellow' : 'green', tooltip: 'Code quality issues classified as warnings for review' },
    ];
    cards.forEach(function(c) {
      var div = document.createElement('div');
      div.className = 'metric-card';
      if (c.tooltip) div.setAttribute('data-tooltip', c.tooltip);
      div.innerHTML = '<div class="value ' + c.cls + '">' + c.value + '</div><div class="label">' + esc(c.label) + '</div>';
      grid.appendChild(div);
    });
  })();

  var qualitySortCol = null, qualitySortAsc = true;

  function renderQualityTable() {
    var findings = DATA.qualityFindings.slice();
    var search = (document.getElementById('quality-search').value || '').toLowerCase();

    // Severity filter
    if (activeSeverity !== 'all') {
      findings = findings.filter(function(f) { return f.severity === activeSeverity; });
    }
    // Search
    if (search) {
      findings = findings.filter(function(f) {
        return (f.file + ' ' + f.rule + ' ' + f.message + ' ' + f.repo + ' ' + f.tool).toLowerCase().indexOf(search) !== -1;
      });
    }
    // Sort
    if (qualitySortCol) {
      findings.sort(function(a, b) {
        var va = a[qualitySortCol], vb = b[qualitySortCol];
        if (va == null) va = '';
        if (vb == null) vb = '';
        if (typeof va === 'number' && typeof vb === 'number') return qualitySortAsc ? va - vb : vb - va;
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        return qualitySortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      });
    }

    document.getElementById('quality-row-count').textContent = 'Showing ' + findings.length + ' of ' + DATA.qualityFindings.length + ' findings';

    var tbody = document.getElementById('quality-tbody');
    var rows = '';
    findings.forEach(function(f) {
      var sevPill = '<span class="severity-pill ' + esc(f.severity) + '">' + esc(f.severity) + '</span>';
      rows += '<tr>';
      rows += '<td>' + esc(f.file) + '</td>';
      rows += '<td>' + f.line + '</td>';
      rows += '<td>' + esc(f.rule) + '</td>';
      rows += '<td>' + esc(f.message) + '</td>';
      rows += '<td>' + sevPill + '</td>';
      rows += '<td>' + esc(f.repo) + '</td>';
      rows += '<td>' + esc(f.tool) + '</td>';
      rows += '</tr>';
    });
    tbody.innerHTML = rows;

    // Sort arrows
    document.querySelectorAll('#quality-table th').forEach(function(th) {
      var arrow = th.querySelector('.sort-arrow');
      if (th.dataset.col === qualitySortCol) {
        arrow.innerHTML = qualitySortAsc ? '&#9650;' : '&#9660;';
      } else {
        arrow.innerHTML = '';
      }
    });
  }

  document.querySelectorAll('#quality-table th').forEach(function(th) {
    th.addEventListener('click', function() {
      var col = th.dataset.col;
      if (qualitySortCol === col) {
        qualitySortAsc = !qualitySortAsc;
      } else {
        qualitySortCol = col;
        qualitySortAsc = true;
      }
      renderQualityTable();
    });
  });

  document.getElementById('quality-search').addEventListener('input', renderQualityTable);
  renderQualityTable();

  // ===== Time-ago Display =====
  (function() {
    function updateTimeAgo() {
      var gen = new Date(DATA.generated);
      var now = new Date();
      var diffMs = now - gen;
      var diffMins = Math.floor(diffMs / 60000);
      var diffHrs = Math.floor(diffMins / 60);
      var diffDays = Math.floor(diffHrs / 24);
      var text;
      if (diffMins < 1) text = 'Just now';
      else if (diffMins < 60) text = diffMins + 'm ago';
      else if (diffHrs < 24) text = diffHrs + 'h ago';
      else text = diffDays + 'd ago';
      document.getElementById('time-ago').textContent = 'Scanned ' + text;
    }
    updateTimeAgo();
    setInterval(updateTimeAgo, 60000);
  })();

  // ===== Toast Utility =====
  function showToast(msg, type) {
    var container = document.getElementById('toast-container');
    var toast = document.createElement('div');
    toast.className = 'toast' + (type ? ' ' + type : '');
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(function() { toast.remove(); }, 3000);
  }

  // ===== Copy Command Button =====
  document.getElementById('btn-copy-cmd').addEventListener('click', function() {
    navigator.clipboard.writeText('npx git-steer scan').then(function() {
      showToast('Copied: npx git-steer scan', 'success');
    }).catch(function() {
      showToast('Failed to copy to clipboard', 'error');
    });
  });

  // ===== Run Security Scan Modal =====
  (function() {
    var modal = document.getElementById('scan-modal');
    var patInput = document.getElementById('pat-input');
    var feedback = document.getElementById('modal-feedback');

    document.getElementById('btn-run-scan').addEventListener('click', function() {
      // Restore saved token if any
      var saved = sessionStorage.getItem('gs_pat');
      if (saved) patInput.value = saved;
      modal.classList.add('active');
      patInput.focus();
    });

    document.getElementById('modal-cancel').addEventListener('click', function() {
      modal.classList.remove('active');
      feedback.textContent = '';
    });

    modal.addEventListener('click', function(e) {
      if (e.target === modal) {
        modal.classList.remove('active');
        feedback.textContent = '';
      }
    });

    document.getElementById('modal-trigger').addEventListener('click', function() {
      var token = patInput.value.trim();
      if (!token) {
        feedback.style.color = '#f85149';
        feedback.textContent = 'Please enter a GitHub PAT token.';
        return;
      }
      sessionStorage.setItem('gs_pat', token);
      feedback.style.color = '#d29922';
      feedback.textContent = 'Triggering workflow...';

      // Try to detect repo from data
      var repos = Object.keys(DATA.metrics.byRepo);
      var firstRepo = repos.length > 0 ? repos[0] : '';
      var owner = firstRepo.split('/')[0] || '';
      var repo = firstRepo.split('/')[1] || '';

      if (!owner || !repo) {
        feedback.style.color = '#f85149';
        feedback.textContent = 'Could not detect repository from dashboard data.';
        return;
      }

      // List workflows to find one to dispatch
      fetch('https://api.github.com/repos/' + owner + '/' + repo + '/actions/workflows', {
        headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github.v3+json' }
      }).then(function(res) { return res.json(); }).then(function(data) {
        if (!data.workflows || data.workflows.length === 0) {
          feedback.style.color = '#f85149';
          feedback.textContent = 'No workflows found. Set up a GitHub Actions workflow first.';
          return;
        }
        // Find a git-steer or security workflow, fallback to first
        var wf = data.workflows.find(function(w) {
          return w.name.toLowerCase().indexOf('steer') !== -1 || w.name.toLowerCase().indexOf('security') !== -1;
        }) || data.workflows[0];

        // Resolve default branch before dispatching
        return fetch('https://api.github.com/repos/' + owner + '/' + repo, {
          headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github.v3+json' }
        }).then(function(r) { return r.json(); }).then(function(repoData) {
          var defaultBranch = (repoData && repoData.default_branch) || 'main';
          return fetch('https://api.github.com/repos/' + owner + '/' + repo + '/actions/workflows/' + wf.id + '/dispatches', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github.v3+json', 'Content-Type': 'application/json' },
            body: JSON.stringify({ ref: defaultBranch })
          });
        }).then(function(res) {
          if (res.status === 204) {
            feedback.style.color = '#3fb950';
            feedback.textContent = 'Workflow dispatched successfully!';
            showToast('Security scan triggered for ' + owner + '/' + repo, 'success');
            setTimeout(function() { modal.classList.remove('active'); feedback.textContent = ''; }, 2000);
          } else {
            return res.json().then(function(err) {
              feedback.style.color = '#f85149';
              feedback.textContent = 'Error: ' + (err.message || res.status);
            });
          }
        });
      }).catch(function(err) {
        feedback.style.color = '#f85149';
        feedback.textContent = 'Network error: ' + err.message;
      });
    });
  })();

  // ===== CSV Export =====
  document.getElementById('btn-export-csv').addEventListener('click', function() {
    var activeTab = document.querySelector('.tab-btn.active').dataset.tab;
    var rows = [];
    var filename = 'git-steer-';

    if (activeTab === 'overview' || activeTab === 'cve-details') {
      filename += 'cves';
      rows.push(['CVE ID','Package','Severity','Fix Version','Repository','Status','RFC #']);
      var vulns = DATA.vulnerabilities;
      if (activeSeverity !== 'all') vulns = vulns.filter(function(v) { return v.severity === activeSeverity; });
      vulns.forEach(function(v) {
        rows.push([v.cve, v.package, v.severity, v.fixVersion, v.repo, v.status, '#' + v.issueNumber]);
      });
    } else if (activeTab === 'repositories') {
      filename += 'repos';
      rows.push(['Repository','Total','Fixed','Open']);
      var byRepo = DATA.metrics.byRepo;
      Object.keys(byRepo).forEach(function(r) {
        var d = byRepo[r];
        rows.push([r, d.total, d.fixed, d.total - d.fixed]);
      });
    } else if (activeTab === 'code-quality') {
      filename += 'quality';
      rows.push(['File','Line','Rule','Message','Severity','Repo','Tool']);
      var findings = DATA.qualityFindings;
      if (activeSeverity !== 'all') findings = findings.filter(function(f) { return f.severity === activeSeverity; });
      findings.forEach(function(f) {
        rows.push([f.file, f.line, f.rule, f.message, f.severity, f.repo, f.tool]);
      });
    }

    var csv = rows.map(function(r) {
      return r.map(function(c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(',');
    }).join('\\n');

    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename + '-' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    URL.revokeObjectURL(url);
    showToast('CSV exported: ' + a.download, 'success');
  });

  // ===== Keyboard Shortcuts =====
  (function() {
    var hintPanel = document.getElementById('kb-hints');
    document.getElementById('kb-hint-btn').addEventListener('click', function() {
      hintPanel.classList.toggle('active');
    });

    document.addEventListener('keydown', function(e) {
      // Don't trigger shortcuts when typing in inputs
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

      var tabs = ['overview','cve-details','repositories','code-quality','about'];
      if (e.key >= '1' && e.key <= '5') {
        var idx = parseInt(e.key) - 1;
        var tabBtn = document.querySelector('[data-tab="' + tabs[idx] + '"]');
        if (tabBtn) tabBtn.click();
      }
      if (e.key === 'Escape') {
        document.getElementById('scan-modal').classList.remove('active');
        hintPanel.classList.remove('active');
      }
      if (e.key === '?') {
        hintPanel.classList.toggle('active');
      }
    });
  })();

  // ===== Click-to-Copy CVE IDs =====
  document.addEventListener('click', function(e) {
    var link = e.target.closest('a[href*="nvd.nist.gov/vuln/detail/"]');
    if (!link) return;
    var cveId = link.textContent.trim();
    if (!cveId || cveId === 'N/A') return;
    navigator.clipboard.writeText(cveId).then(function() {
      var flash = document.createElement('span');
      flash.className = 'copy-flash';
      flash.textContent = 'Copied!';
      link.style.position = 'relative';
      link.appendChild(flash);
      setTimeout(function() { flash.remove(); }, 1200);
    });
  });

  // ===== Fullscreen Toggle =====
  document.getElementById('fullscreen-btn').addEventListener('click', function() {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(function() {});
    } else {
      document.exitFullscreen();
    }
  });
  </script>
</body>
</html>`;
}
