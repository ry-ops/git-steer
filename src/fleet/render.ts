/**
 * Renders the fleet dashboard issue body from status.json (ADR-009).
 *
 * "Needs you" lists only what a machine can't decide (C-008-008). Findings
 * are shown per tool only where that tool is on; anything else is UNKNOWN,
 * never zero (C-009-001).
 */

import type { CoverageKey, CoverageState, FleetStatus, RepoStatus, SeverityCounts } from './types.js';

/** GitHub's issue body limit is 65,536 characters; stay well under it. */
export const MAX_BODY = 60_000;

export const COVERAGE_LABELS: Record<CoverageKey, string> = {
  dependabotAlerts: 'Dependabot alerts',
  dependabotSecurityUpdates: 'Dependabot fix PRs',
  codeScanning: 'Code scanning',
  secretScanning: 'Secret scanning',
  pushProtection: 'Push protection',
  branchProtection: 'Branch protection',
};

export const KEYS = Object.keys(COVERAGE_LABELS) as CoverageKey[];

export interface DecisionCounts {
  noPatch: number;
  stalePrs: number;
  undocumentedDismissals: number;
  settingsOff: number;
  unprotected: number;
  unknown: number;
}

export function decisionCounts(status: FleetStatus): DecisionCounts {
  const r = status.repos;
  return {
    noPatch: r.reduce((n, x) => n + x.findings.noPatch.length, 0),
    stalePrs: r.reduce((n, x) => n + x.findings.staleDependabotPrs.length, 0),
    undocumentedDismissals: r.reduce((n, x) => n + x.findings.undocumentedDismissals.length, 0),
    settingsOff: r.filter((x) => offDetectors(x).length > 0).length,
    unprotected: r.filter((x) => x.coverage.branchProtection === 'off').length,
    unknown: r.filter((x) => KEYS.some((k) => x.coverage[k] === 'unknown') || x.errors.length > 0).length,
  };
}

/** Settings that are off and can be turned on, other than branch protection (listed on its own). */
function offDetectors(r: RepoStatus): string[] {
  return KEYS.filter((k) => k !== 'branchProtection' && r.coverage[k] === 'off').map((k) => COVERAGE_LABELS[k]);
}

function sum(counts: (SeverityCounts | null)[]): SeverityCounts {
  const total = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const c of counts) {
    if (!c) continue;
    total.critical += c.critical;
    total.high += c.high;
    total.medium += c.medium;
    total.low += c.low;
  }
  return total;
}

export function sev(c: SeverityCounts): string {
  return `${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low`;
}

export function cell(state: CoverageState): string {
  return { on: '✅', off: '❌', unavailable: '—', unknown: '❓' }[state];
}

/** Table rows, cut to `max` with a pointer to status.json for the rest. */
function rows(lines: string[], max: number): string[] {
  if (lines.length <= max) return lines;
  return [...lines.slice(0, max), `| …and ${lines.length - max} more in status.json | |`];
}

export function renderDashboard(status: FleetStatus, maxRows = 50): string {
  const body = render(status, maxRows);
  if (body.length <= MAX_BODY || maxRows <= 5) return body;
  return renderDashboard(status, Math.floor(maxRows / 2));
}

function render(status: FleetStatus, maxRows: number): string {
  const repos = status.repos;
  const pub = repos.filter((r) => !r.private).length;
  const d = decisionCounts(status);
  const needs = d.noPatch + d.stalePrs + d.undocumentedDismissals + d.settingsOff + d.unprotected;
  const out: string[] = [];

  out.push('# git-steer fleet dashboard', '');
  out.push(`Updated ${status.generatedAt.replace('T', ' ').slice(0, 16)} UTC by \`${status.app}\`${status.runUrl ? ` · [run](${status.runUrl})` : ''} · ${repos.length} repos (${pub} public, ${repos.length - pub} private)`, '');
  out.push(`**Open Dependabot alerts:** ${sev(sum(repos.map((r) => r.findings.dependabot)))}  `);
  out.push(`**Open code scanning alerts:** ${sev(sum(repos.map((r) => r.findings.codeScanning)))}  `);
  out.push(`**Open secret scanning alerts:** ${repos.reduce((n, r) => n + (r.findings.secretScanning ?? 0), 0)}`, '');

  out.push(`## Needs you (${needs})`, '');
  if (needs === 0) out.push('Nothing needs a human decision right now. 🎉', '');

  const noPatch = repos.flatMap((r) => r.findings.noPatch.map((a) =>
    `| ${r.repo} | [${a.ghsa || '#' + a.number}](${a.url}) | ${a.package} | ${a.severity} |`));
  if (noPatch.length) {
    out.push(`### Alerts with no fix available (${noPatch.length})`, '', 'No patched version exists. Decide: accept the risk (dismiss with a reason), remove the dependency, or wait.', '');
    out.push('| Repo | Alert | Package | Severity |', '|---|---|---|---|', ...rows(noPatch, maxRows), '');
  }

  const stale = repos.flatMap((r) => r.findings.staleDependabotPrs.map((p) =>
    `| ${r.repo} | [#${p.number}](${p.url}) ${p.title.replace(/\|/g, '/')} | ${p.ageDays} days |`));
  if (stale.length) {
    out.push(`### Dependabot PRs open more than 14 days (${stale.length})`, '');
    out.push('| Repo | PR | Open for |', '|---|---|---|', ...rows(stale, maxRows), '');
  }

  const dismissed = repos.flatMap((r) => r.findings.undocumentedDismissals.map((a) =>
    `| ${r.repo} | [${a.ghsa || '#' + a.number}](${a.url}) | ${a.package} |`));
  if (dismissed.length) {
    out.push(`### Dismissed alerts with no reason (${dismissed.length})`, '', 'A VEX statement needs a justification. Add a comment to each dismissal.', '');
    out.push('| Repo | Alert | Package |', '|---|---|---|', ...rows(dismissed, maxRows), '');
  }

  const off = repos.filter((r) => offDetectors(r).length).map((r) => `| ${r.repo} | ${offDetectors(r).join(', ')} |`);
  if (off.length) {
    out.push(`### Settings turned off (${off.length} repos)`, '', 'Free to turn on. Off means findings for that tool are unknown.', '');
    out.push('| Repo | Off |', '|---|---|', ...rows(off, maxRows), '');
  }

  const unprotected = repos.filter((r) => r.coverage.branchProtection === 'off').map((r) => r.repo);
  if (unprotected.length) {
    out.push(`### No branch protection (${unprotected.length} repos)`, '');
    const shown = unprotected.slice(0, maxRows * 2).join(', ');
    out.push(unprotected.length > maxRows * 2 ? `${shown}, …and ${unprotected.length - maxRows * 2} more in status.json` : shown, '');
  }

  out.push('## Fleet at a glance', '');
  out.push('| Owner | Repos | Dependabot (crit/high/med/low) | Code scanning (crit/high/med/low) | Secrets | Coverage gaps |', '|---|---|---|---|---|---|');
  for (const o of status.owners) {
    const mine = repos.filter((r) => r.owner === o.account);
    const dep = sum(mine.map((r) => r.findings.dependabot));
    const code = sum(mine.map((r) => r.findings.codeScanning));
    const gaps = mine.filter((r) => KEYS.some((k) => r.coverage[k] === 'off' || r.coverage[k] === 'unknown')).length;
    out.push(`| ${o.account} | ${mine.length} | ${dep.critical}/${dep.high}/${dep.medium}/${dep.low} | ${code.critical}/${code.high}/${code.medium}/${code.low} | ${mine.reduce((n, r) => n + (r.findings.secretScanning ?? 0), 0)} | ${gaps} |`);
  }
  out.push('', 'Counts only include tools that are on. A repo with a tool off or unknown is in "Coverage gaps", not counted as clean.', '');

  out.push('## Coverage', '');
  out.push('✅ on · ❌ off · — not on this plan · ❓ unknown', '');
  out.push('| Check | ✅ | ❌ | — | ❓ |', '|---|---|---|---|---|');
  for (const k of KEYS) {
    const n = (s: CoverageState) => repos.filter((r) => r.coverage[k] === s).length;
    out.push(`| ${COVERAGE_LABELS[k]} | ${n('on')} | ${n('off')} | ${n('unavailable')} | ${n('unknown')} |`);
  }
  out.push('');

  const unknown = repos.filter((r) => KEYS.some((k) => r.coverage[k] === 'unknown') || r.errors.length);
  if (unknown.length) {
    out.push(`<details><summary>Repos git-steer couldn't fully read (${unknown.length})</summary>`, '', '| Repo | Unknown | Errors |', '|---|---|---|');
    out.push(...rows(unknown.map((r) => `| ${r.repo} | ${KEYS.filter((k) => r.coverage[k] === 'unknown').map((k) => cell('unknown') + ' ' + COVERAGE_LABELS[k]).join(', ')} | ${r.errors.join('; ')} |`), maxRows));
    out.push('', '</details>', '');
  }

  out.push('---', '', `Generated by git-steer from \`status.json\` (${status.schema}). This issue is updated in place; edits to it are overwritten.`);
  return out.join('\n') + '\n';
}
