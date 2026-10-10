/**
 * Hand off to Copilot (ADR-011): issues in the target repo for the work
 * Dependabot can't do, written so the Copilot coding agent (or a person, or
 * another agent) can pick them up.
 *
 *   - one CI issue when nothing proves a Dependabot PR works: "add CI" when
 *     nothing builds or tests the repo, "fix CI" when its checks fail on the
 *     default branch or on every Dependabot PR. This comes first: until a
 *     repo has passing CI, Fix can't merge its PRs safely;
 *   - one "upgrade" issue for fixable alerts no open Dependabot PR reaches;
 *   - one "replace" issue per package that has no fixed version at all.
 *
 * "handoff ci <owner>" and "handoff ci fleet" file only the CI issue, in every
 * repo with open Dependabot PRs that needs one (at most MAX_CI_REPOS).
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
import { parseScanTarget } from './scan.js';
import type { CveAlert } from './types.js';

export const MAX_HANDOFFS = 5;
export const MAX_CI_REPOS = 30;

export type HandoffRequest = { repo: string } | { ci: true; owner?: string };

/** "handoff owner/repo", "handoff ci <owner>" or "handoff ci fleet|all". */
export function parseHandoffRequest(title: string, body = ''): HandoffRequest | null {
  const ci = title.trim().match(/^hand-?off:?\s+ci\s+([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\s*$/i);
  if (ci) {
    const scope = ci[1].toLowerCase();
    return { ci: true, owner: scope === 'fleet' || scope === 'all' ? undefined : ci[1] };
  }
  const repo = parseScanTarget(`${title}\n${body}`);
  return repo ? { repo } : null;
}
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

export type CiNeed =
  | { kind: 'missing'; scanners: string[] }
  | { kind: 'broken'; where: 'default'; sha: string; checks: string[] }
  | { kind: 'broken'; where: 'prs'; failing: number; of: number; checks: [string, number][] };

function failedNames(detail: string): string[] {
  const m = detail.match(/^failed: (.*?)(?: \(commit statuses not readable.*\))?$/);
  return m ? m[1].split(', ').filter(Boolean) : [];
}

/**
 * Whether the repo's CI stands in the way of merging its Dependabot PRs.
 * Any passing test, on the default branch or on a PR, means CI works: a PR
 * that fails then is a real breaking upgrade, not a CI problem. Checks still
 * running on the default branch, or unreadable, mean "don't know": no issue.
 */
export function ciNeed(plan: FixPlan): CiNeed | null {
  const main = plan.ci?.main ?? null;
  if (main?.state === 'failing') return { kind: 'broken', where: 'default', sha: main.sha, checks: failedNames(main.detail) };
  if (main?.state === 'ready' || plan.prs.some((p) => p.state === 'ready')) return null;
  const failing = plan.prs.filter((p) => p.state === 'failing');
  if (failing.length) {
    const tally = new Map<string, number>();
    for (const p of failing) for (const n of new Set(failedNames(p.detail))) tally.set(n, (tally.get(n) ?? 0) + 1);
    const checks = [...tally].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const of = plan.prs.filter((p) => p.state !== 'skip').length;
    return { kind: 'broken', where: 'prs', failing: failing.length, of, checks };
  }
  if (!main || main.state === 'running') return null;
  const scanners = [...new Set((main.detail.match(/^only scanners passed \((.*)\);/)?.[1] ?? '').split(', ').filter(Boolean))];
  return { kind: 'missing', scanners };
}

const SIGN_OFF = ['', '---', '', 'Opened by git-steer (Hand off). Assign it to Copilot, or to whoever should do it.'];

export function buildCiHandoff(plan: FixPlan): Handoff | null {
  const need = ciNeed(plan);
  if (!need) return null;
  const branch = plan.scan.status.defaultBranch;
  const open = plan.prs.filter((p) => p.state !== 'skip').length;
  const prs = open ? `${open} Dependabot pull request${open === 1 ? ' is' : 's are'} open, and` : 'When Dependabot opens pull requests,';
  const workflows = plan.ci?.workflows;
  const existing = workflows?.length ? `Workflows already here: ${workflows.map((w) => `\`${w}\``).join(', ')}.` : workflows ? 'There is no `.github/workflows` folder yet.' : '';

  if (need.kind === 'missing') {
    const key = `${plan.repo}:ci:add`;
    const lines = [
      marker(key),
      `Nothing in this repo builds or tests a change before it merges. ${prs} git-steer won't merge them on its own, because no check shows an upgrade still works.`,
      '',
      ...(need.scanners.length ? [`The checks that do run are scanners or linters (${need.scanners.join(', ')}). They read the code but don't build or run it.`, ''] : []),
      ...(existing ? [existing, ''] : []),
      '### Add',
      '',
      `- A workflow, \`.github/workflows/ci.yml\`, that runs on \`pull_request\` and on \`push\` to \`${branch}\`.`,
      '- It installs dependencies from the lockfile, builds the project, and runs its tests. Cover each language or package the repo has (for example, every folder with its own manifest).',
      '- If there are no tests, add a small smoke test, such as the main module loading or the program starting and printing its version, so a passing run means something.',
      '- Name the job `build-and-test`. git-steer treats checks whose names mention lint, scan, security, audit or analyze as scanners, not tests.',
      '- Give it `permissions: contents: read`, and pin each action to a full commit SHA with the version in a comment.',
      '- It must run without repository secrets: Dependabot pull requests don\'t receive them.',
      '',
      '### Done when',
      '',
      '- The new check runs and passes on the pull request that adds it.',
      '- The pull request lists what the workflow builds and tests, and anything it leaves out and why.',
      ...SIGN_OFF,
    ];
    return { key, title: 'Add CI that builds and tests this repo', body: lines.join('\n') + '\n' };
  }

  const key = `${plan.repo}:ci:fix`;
  const what = need.where === 'default'
    ? [`The latest commit on \`${branch}\` (${need.sha.slice(0, 7)}) fails: ${need.checks.map((c) => `\`${c}\``).join(', ') || 'see its checks'}.`]
    : [
      `${need.failing} of ${need.of} open Dependabot pull requests fail their checks, and none pass. That points at CI, not at the upgrades:`,
      '',
      '| Check | Failing PRs |',
      '|---|---|',
      ...need.checks.slice(0, 10).map(([c, n]) => `| \`${c}\` | ${n} |`),
    ];
  const lines = [
    marker(key),
    ...what,
    '',
    `Until these pass, git-steer can't tell a broken upgrade from broken CI, so it merges none of the Dependabot pull requests here.`,
    '',
    ...(existing ? [existing, ''] : []),
    '### How',
    '',
    `- Start from the most recent failed run${need.where === 'default' ? ` on \`${branch}\`` : ''} and its log.`,
    '- Fix the cause: the code, the build config, an outdated action or runtime version, a missing file.',
    '- If a job needs a secret or a service that pull requests (Dependabot\'s especially) don\'t get, make it skip cleanly there and still run where it can, rather than fail.',
    '- Don\'t delete tests, mark them skipped, or add `continue-on-error` to get a green run.',
    '',
    '### Done when',
    '',
    `- The checks above pass on the pull request${need.where === 'default' ? ` and on \`${branch}\` after it merges` : ''}.`,
    '- Anything that can\'t be fixed inside the repo (a secret, an outside service) is named in the pull request, with what it needs.',
    ...SIGN_OFF,
  ];
  const title = need.where === 'default' ? `Fix the failing CI on \`${branch}\`` : 'Fix the CI that fails on every Dependabot pull request';
  return { key, title, body: lines.join('\n') + '\n' };
}

export function buildHandoffs(plan: FixPlan, max = MAX_HANDOFFS): Handoff[] {
  const repo = plan.repo;
  const isPrivate = plan.scan.status.private;
  const ci = buildCiHandoff(plan);
  const out: Handoff[] = ci ? [ci] : [];

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
    lines.push(...SIGN_OFF);
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
    lines.push(...SIGN_OFF);
    out.push({ key, title: `Remove or replace \`${pkg}\` (no fixed release)`, body: lines.join('\n') + '\n' });
  }

  return out.slice(0, max);
}

/** One repo's issues to open, as written to handoff-plan.json. */
export interface HandoffTarget {
  repo: string;
  owner: string;
  name: string;
  url: string;
  private: boolean;
  handoffs: Handoff[];
}

export interface HandoffPlanFile {
  /** The repo, or for a CI request the owner or "fleet". */
  scope: string;
  ci: boolean;
  targets: HandoffTarget[];
  /** Hand-offs (one repo) or repos (CI request) left for a later request. */
  dropped: number;
  /** Repos planned whose CI already works, for a CI request. */
  healthy: number;
  errors: { repo: string; message: string }[];
}

function target(plan: FixPlan, handoffs: Handoff[]): HandoffTarget {
  const [owner, name] = plan.repo.split('/');
  return { repo: plan.repo, owner, name, url: plan.scan.status.url, private: plan.scan.status.private, handoffs };
}

/** Everything a one-repo hand-off would file, at most MAX_HANDOFFS. */
export function planRepoHandoffs(plan: FixPlan): HandoffPlanFile {
  const all = buildHandoffs(plan, Infinity);
  const handoffs = all.slice(0, MAX_HANDOFFS);
  return { scope: plan.repo, ci: false, targets: handoffs.length ? [target(plan, handoffs)] : [], dropped: all.length - handoffs.length, healthy: 0, errors: [] };
}

/** One CI issue per repo that needs one, most open Dependabot PRs first, at most MAX_CI_REPOS. */
export function planCiHandoffs(scope: string, plans: FixPlan[], errors: HandoffPlanFile['errors'] = []): HandoffPlanFile {
  const open = (p: FixPlan) => p.prs.filter((x) => x.state !== 'skip').length;
  const needing = plans
    .map((p) => ({ p, h: buildCiHandoff(p) }))
    .filter((x): x is { p: FixPlan; h: Handoff } => x.h !== null)
    .sort((a, b) => open(b.p) - open(a.p) || a.p.repo.localeCompare(b.p.repo));
  const kept = needing.slice(0, MAX_CI_REPOS);
  return {
    scope, ci: true, targets: kept.map(({ p, h }) => target(p, [h])),
    dropped: needing.length - kept.length, healthy: plans.length - needing.length, errors,
  };
}

export interface HandoffResult {
  repo: string;
  key: string;
  title: string;
  url: string;
  state: 'opened' | 'already-open' | 'failed';
  detail?: string;
}

const STATUS = (r: HandoffResult) => ({ opened: '🆕 opened', 'already-open': '↩️ already open', failed: `❌ failed: ${r.detail ?? ''}` }[r.state]);
const LINK = (r: HandoffResult) => (r.url ? `[${r.title}](${r.url})` : r.title);
const ASSIGN = 'Open each issue and **Assign to Copilot** (Assignees → Copilot), from github.com or the mobile app. Copilot opens a pull request; review it like any other. git-steer never assigns these itself.';

/**
 * The reply on the request. A hand-off the plan listed but no result came back
 * for (its job never ran) shows as not opened.
 */
export function renderHandoffReply(plan: HandoffPlanFile, results: HandoffResult[]): string {
  const got = (t: HandoffTarget, h: Handoff): HandoffResult =>
    results.find((r) => r.repo === t.repo && r.key === h.key) ?? { repo: t.repo, key: h.key, title: h.title, url: '', state: 'failed', detail: 'not opened (see the run)' };
  const out: string[] = [];

  if (!plan.ci) {
    const t = plan.targets[0];
    out.push(`## git-steer hand-off: ${t ? `[${t.repo}](${t.url})` : plan.scope}`, '');
    if (!t) {
      out.push('Nothing to hand off: CI works (or couldn\'t be read), and every open alert either has a Dependabot PR or none could be read.', '', 'Use 🩹 Fix a repo to merge the Dependabot PRs.');
    } else {
      out.push('| Issue | Status |', '|---|---|', ...t.handoffs.map((h) => { const r = got(t, h); return `| ${LINK(r)} | ${STATUS(r)} |`; }));
      if (plan.dropped) out.push('', `${plan.dropped} more hand-off(s) held back (at most ${MAX_HANDOFFS} per request). Ask again once these are done.`);
      out.push('', '### Next', '', ASSIGN);
      if (t.handoffs.some((h) => h.key.endsWith(':ci:add') || h.key.endsWith(':ci:fix'))) out.push('', 'Do the CI issue first: once a check really builds and tests the repo, 🩹 Fix can merge its Dependabot PRs safely.');
      if (!t.private) out.push('', `${t.repo} is public, so the issues name packages and target versions only, with no advisory details (C-009-003).`);
    }
    out.push('', '---', '', 'git-steer wrote only these issues in the target repo. Nothing else was changed.');
    return out.join('\n') + '\n';
  }

  out.push(`## git-steer hand-off: CI for ${plan.scope}`, '');
  if (!plan.targets.length) {
    out.push(`Nothing to hand off: ${plan.healthy} repo(s) with open Dependabot PRs have CI that works, or CI that couldn't be read.`);
  } else {
    out.push('| Repo | Issue | Status |', '|---|---|---|');
    for (const t of plan.targets) for (const h of t.handoffs) { const r = got(t, h); out.push(`| [${t.repo}](${t.url}) | ${LINK(r)} | ${STATUS(r)} |`); }
    out.push('', `${plan.healthy} other repo(s) with open Dependabot PRs already have CI that works, or CI git-steer couldn't judge.`);
    if (plan.dropped) out.push('', `${plan.dropped} more repo(s) held back (at most ${MAX_CI_REPOS} per request). Ask again once these are done.`);
    out.push('', '### Next', '', ASSIGN, '', 'As each PR merges, the next 🩹 `fix fleet` finds those repos\' Dependabot PRs tested and puts them on its rollout.');
  }
  if (plan.errors.length) out.push('', '### Couldn\'t plan', '', ...plan.errors.map((e) => `- ${e.repo}: ${e.message}`));
  out.push('', '---', '', 'git-steer wrote only these issues, one per repo. Nothing else was changed.');
  return out.join('\n') + '\n';
}
