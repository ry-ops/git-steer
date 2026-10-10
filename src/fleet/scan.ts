/**
 * Renders a single-repo scan as an issue comment (ADR-009 Layer 2, one repo).
 *
 * Same rules as the dashboard: a tool's findings are shown only where the
 * tool is on, and anything else is UNKNOWN, never zero (C-009-001).
 */

import { cell, COVERAGE_LABELS, KEYS, MAX_BODY, sev } from './render.js';
import type { CveAlert, RepoScan, SeverityCounts } from './types.js';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'moderate', 'low'];

/** Finds the owner/repo a request names: "scan owner/repo", "scan: owner/repo" or a github.com URL. */
export function parseScanTarget(text: string): string | null {
  const m = text.match(/(?:github\.com\/)?([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\/([A-Za-z0-9._-]+?)(?:\.git)?(?:[/#?\s]|$)/);
  if (!m || m[2] === '.' || m[2] === '..') return null;
  return `${m[1]}/${m[2]}`;
}

function rank(severity: string): number {
  const i = SEVERITY_ORDER.indexOf(severity.toLowerCase());
  return i === -1 ? SEVERITY_ORDER.length : i;
}

function counts(c: SeverityCounts | null): string {
  return c ? sev(c) : 'unknown (not on)';
}

function alertRow(a: CveAlert): string {
  const advisory = `[${a.ghsa || '#' + a.number}](${a.url})`;
  return `| ${a.severity} | ${a.package} (${a.ecosystem}) | ${advisory} | ${a.cve ?? '—'} | ${a.fixedIn ?? '**no fix yet**'} | ${a.manifest} |`;
}

export function renderScan(scan: RepoScan, maxRows = 100): string {
  const body = render(scan, maxRows);
  if (body.length <= MAX_BODY || maxRows <= 5) return body;
  return renderScan(scan, Math.floor(maxRows / 2));
}

function render(scan: RepoScan, maxRows: number): string {
  const r = scan.status;
  const f = r.findings;
  const out: string[] = [];

  out.push(`## git-steer scan: [${r.repo}](${r.url})`, '');
  out.push(`Scanned ${scan.generatedAt.replace('T', ' ').slice(0, 16)} UTC by \`${scan.app}\`${scan.runUrl ? ` · [run](${scan.runUrl})` : ''} · ${r.private ? 'private' : 'public'} · \`${r.defaultBranch}\`${scan.archived ? ' · **archived**' : ''}`, '');
  out.push(`**Dependabot alerts:** ${counts(f.dependabot)}  `);
  out.push(`**Code scanning alerts:** ${counts(f.codeScanning)}  `);
  out.push(`**Secret scanning alerts:** ${f.secretScanning ?? 'unknown (not on)'}`, '');

  if (scan.alerts === null) {
    out.push('### Dependabot alerts', '', r.coverage.dependabotAlerts === 'on'
      ? 'Dependabot alerts are on, but git-steer couldn\'t read them. See the errors below.'
      : 'Dependabot alerts aren\'t on for this repo, so its CVEs are unknown, not zero.', '');
  } else if (scan.alerts.length === 0) {
    out.push('### Dependabot alerts', '', 'No open Dependabot alerts. ✅', '');
  } else {
    const sorted = [...scan.alerts].sort((a, b) => rank(a.severity) - rank(b.severity) || a.package.localeCompare(b.package));
    const lines = sorted.map(alertRow);
    out.push(`### Open Dependabot alerts (${sorted.length})`, '');
    out.push('| Severity | Package | Advisory | CVE | Fixed in | Manifest |', '|---|---|---|---|---|---|');
    out.push(...lines.slice(0, maxRows));
    if (lines.length > maxRows) out.push(`| …and ${lines.length - maxRows} more | | | | | |`);
    out.push('');
  }

  const needs: string[] = [];
  if (f.noPatch.length) needs.push(`- ${f.noPatch.length} alert(s) have no fixed version yet: accept the risk (dismiss with a reason), remove the dependency, or wait.`);
  for (const p of f.staleDependabotPrs) needs.push(`- Dependabot PR [#${p.number}](${p.url}) has been open ${p.ageDays} days: ${p.title}`);
  if (f.undocumentedDismissals.length) needs.push(`- ${f.undocumentedDismissals.length} dismissed alert(s) have no reason recorded.`);
  const off = KEYS.filter((k) => r.coverage[k] === 'off').map((k) => COVERAGE_LABELS[k]);
  if (off.length) needs.push(`- Turned off: ${off.join(', ')}.`);
  out.push('### Needs you', '', ...(needs.length ? needs : ['Nothing needs a human decision. 🎉']), '');

  out.push('<details><summary>Coverage</summary>', '', '✅ on · ❌ off · — not on this plan · ❓ unknown', '', '| Check | State |', '|---|---|');
  for (const k of KEYS) out.push(`| ${COVERAGE_LABELS[k]} | ${cell(r.coverage[k])} |`);
  out.push('', '</details>', '');

  if (r.errors.length) out.push(`**Couldn't read:** ${r.errors.join('; ')}`, '');

  out.push('---', '', 'Read-only scan by git-steer (GET requests only). Nothing in the repo was changed.');
  return out.join('\n') + '\n';
}
