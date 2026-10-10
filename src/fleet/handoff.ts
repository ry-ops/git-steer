/**
 * Hand off to Copilot (ADR-011): issues in the target repo for the work
 * Dependabot can't do, written so the Copilot coding agent (or a person, or
 * another agent) can pick them up.
 *
 *   - one "upgrade" issue for fixable alerts no open Dependabot PR reaches;
 *   - one "replace" issue per package that has no fixed version at all.
 *
 * A public repo's issues are public, and fleet vulnerability data never goes
 * anywhere public (C-009-003): there the issue names packages and the
 * versions to reach, the way any dependency chore would, and no advisory IDs,
 * severities or links. A private repo's issue carries the full detail.
 *
 * git-steer never assigns the issue; the owner does (C-011-004).
 */

import { compareVersions } from './fix.js';
import type { FixPlan } from './fix.js';
import type { CveAlert } from './types.js';

export const MAX_HANDOFFS = 5;
const MARKER = 'git-steer-handoff:v1';

export interface Handoff {
  /** Stable per repo and task, so a repeat request finds the open issue instead of filing a twin. */
  key: string;
  title: string;
  body: string;
}

export function marker(key: string): string {
  return `<!-- ${MARKER} ${JSON.stringify({ key })} -->`;
}

export function markerKey(body: string): string | null {
  const m = body.match(/<!-- git-steer-handoff:v1 (\{.*?\}) -->/);
  if (!m) return null;
  try { return (JSON.parse(m[1]) as { key?: string }).key ?? null; } catch { return null; }
}

function byPackage(alerts: CveAlert[]): Map<string, CveAlert[]> {
  const out = new Map<string, CveAlert[]>();
  for (const a of alerts) out.set(a.package, [...(out.get(a.package) ?? []), a]);
  return out;
}

/** The lowest version that fixes every listed alert for one package. */
export function targetVersion(alerts: CveAlert[]): string | null {
  const fixes = alerts.map((a) => a.fixedIn).filter((v): v is string => !!v);
  return fixes.length ? fixes.reduce((hi, v) => (compareVersions(v, hi) > 0 ? v : hi)) : null;
}

function howTo(ecosystem: string): string[] {
  if (ecosystem === 'npm') {
    return [
      '- Find what pulls each package in: `npm ls <package>`.',
      '- Prefer upgrading the direct dependency that brings it in. If that isn\'t possible, pin it with `overrides` in `package.json`.',
      '- Regenerate `package-lock.json` with `npm install`; don\'t edit the lockfile by hand.',
      '- Confirm with `npm audit` that the packages above no longer report.',
    ];
  }
  return [
    `- Upgrade each package in the table above in its manifest (${ecosystem}), directly or through the dependency that brings it in.`,
    '- Regenerate the lockfile with the package manager; don\'t edit it by hand.',
  ];
}

const DONE = [
  '### Done when',
  '',
  '- Every package in the table above is at or above its target version (or removed).',
  '- The project still builds, and its tests pass if it has any.',
  '- The change is limited to dependency manifests and lockfiles, plus code changes the upgrades strictly require.',
  '- One pull request, with a short list of what moved from which version to which.',
];

function detailRows(alerts: CveAlert[]): string[] {
  return alerts.map((a) => `| ${a.package} | ${a.severity} | [${a.ghsa}](${a.url})${a.cve ? ` ${a.cve}` : ''} | ${a.fixedIn ?? 'no fix'} | ${a.relationship ?? ''} ${a.scope ?? ''} |`);
}

export function buildHandoffs(plan: FixPlan): Handoff[] {
  const repo = plan.repo;
  const isPrivate = plan.scan.status.private;
  const out: Handoff[] = [];

  if (plan.uncovered.length) {
    const pkgs = [...byPackage(plan.uncovered)].sort((a, b) => a[0].localeCompare(b[0]));
    const eco = plan.uncovered[0].ecosystem;
    const key = `${repo}:upgrade`;
    const lines = [
      marker(key),
      'Some dependencies need upgrading, and Dependabot hasn\'t opened pull requests for them.',
      '',
      '### Upgrade',
      '',
      '| Package | To at least | Manifest | Comes in as |',
      '|---|---|---|---|',
      ...pkgs.map(([pkg, list]) => `| \`${pkg}\` | ${targetVersion(list)} | ${[...new Set(list.map((a) => a.manifest))].join(', ')} | ${[...new Set(list.map((a) => [a.relationship, a.scope].filter(Boolean).join(', ')))].join('; ') || '—'} |`),
      '',
      '### How',
      '',
      ...howTo(eco),
      '',
      ...DONE,
    ];
    if (isPrivate) {
      lines.push('', '<details><summary>Advisories (private repo)</summary>', '', '| Package | Severity | Advisory | Fixed in | Relationship |', '|---|---|---|---|---|', ...detailRows(plan.uncovered), '', '</details>');
    }
    lines.push('', '---', '', 'Opened by git-steer (Hand off). Assign it to Copilot, or to whoever should do it.');
    out.push({ key, title: `Upgrade ${pkgs.length} dependenc${pkgs.length === 1 ? 'y' : 'ies'} Dependabot hasn't`, body: lines.join('\n') + '\n' });
  }

  for (const [pkg, list] of [...byPackage(plan.noFix)].sort((a, b) => a[0].localeCompare(b[0]))) {
    const key = `${repo}:replace:${pkg}`;
    const eco = list[0].ecosystem;
    const lines = [
      marker(key),
      `\`${pkg}\` has no fixed release to upgrade to. Remove it, or replace it with a maintained alternative.`,
      '',
      '### How',
      '',
      eco === 'npm' ? `- Find what pulls it in: \`npm ls ${pkg}\`.` : `- Find what pulls it in (${eco}).`,
      `- If code here uses \`${pkg}\` directly, replace those calls (for an HTTP client, the platform's built-in \`fetch\` is usually enough).`,
      `- If it comes in through another dependency, upgrade or replace that dependency so \`${pkg}\` drops out of the lockfile.`,
      '- Regenerate the lockfile with the package manager; don\'t edit it by hand.',
      '',
      '### Done when',
      '',
      `- \`${pkg}\` is no longer in ${[...new Set(list.map((a) => `\`${a.manifest}\``))].join(', ')}.`,
      '- The project still builds, and its tests pass if it has any.',
      '- Behaviour is unchanged; the pull request explains anything that had to change.',
    ];
    if (isPrivate) {
      lines.push('', '<details><summary>Advisories (private repo)</summary>', '', '| Package | Severity | Advisory | Fixed in | Relationship |', '|---|---|---|---|---|', ...detailRows(list), '', '</details>');
    }
    lines.push('', '---', '', 'Opened by git-steer (Hand off). Assign it to Copilot, or to whoever should do it.');
    out.push({ key, title: `Remove or replace \`${pkg}\` (no fixed release)`, body: lines.join('\n') + '\n' });
  }

  return out.slice(0, MAX_HANDOFFS);
}

export interface HandoffResult {
  key: string;
  title: string;
  url: string;
  state: 'opened' | 'already-open' | 'failed';
  detail?: string;
}

export function renderHandoffReply(plan: FixPlan, results: HandoffResult[], dropped: number): string {
  const out = [`## git-steer hand-off: [${plan.repo}](${plan.scan.status.url})`, ''];
  if (!results.length) {
    out.push('Nothing to hand off: every open alert either has a Dependabot PR or none could be read.', '', 'Use 🩹 Fix a repo to merge the Dependabot PRs.');
  } else {
    out.push('| Issue | Status |', '|---|---|');
    for (const r of results) {
      const status = { opened: '🆕 opened', 'already-open': '↩️ already open', failed: `❌ failed: ${r.detail ?? ''}` }[r.state];
      out.push(`| ${r.url ? `[${r.title}](${r.url})` : r.title} | ${status} |`);
    }
    if (dropped) out.push('', `${dropped} more hand-off(s) held back (at most ${MAX_HANDOFFS} per request). Ask again once these are done.`);
    out.push('', '### Next', '', 'Open each issue and **Assign to Copilot** (Assignees → Copilot), from github.com or the mobile app. Copilot opens a pull request; review it like any other. git-steer never assigns these itself.');
    if (!plan.scan.status.private) out.push('', `${plan.repo} is public, so the issues name packages and target versions only, with no advisory details (C-009-003).`);
  }
  out.push('', '---', '', 'git-steer wrote only these issues in the target repo. Nothing else was changed.');
  return out.join('\n') + '\n';
}
