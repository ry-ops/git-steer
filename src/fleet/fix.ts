/**
 * Fix a repo: the plan (ADR-011). Read-only, through the reporter App.
 *
 * Lists the repo's open Dependabot PRs, each with its checks and the open
 * alerts it would close, and what no PR covers. The ready, untested and
 * waiting PRs become the targets of a merge-dependabot-pr rollout the owner
 * approves; failing ones are listed and never merged (C-011-003).
 */

import type { App, Octokit } from 'octokit';
import { getPull, judgePull, readChecks } from '../rollout/changes/merge-dependabot-pr.js';
import type { ChecksVerdict } from '../rollout/changes/merge-dependabot-pr.js';
import { repoOctokit, scanRepo } from './collect.js';
import { parseScanTarget, verdict } from './scan.js';
import type { CveAlert, RepoScan } from './types.js';

export type PlanState = 'ready' | 'untested' | 'waiting' | 'failing' | 'skip';

export interface PackageUpdate { name: string; from: string; to: string }

export type Bump = 'minor' | 'major' | 'unknown';

export interface PlannedPr {
  number: number;
  title: string;
  url: string;
  state: PlanState;
  detail: string;
  updates: PackageUpdate[];
  closes: CveAlert[];
  /** The largest semver step among its updates. A 0.x minor counts as major. */
  bump: Bump;
}

/** What goes on a fix rollout. Failing PRs never do (C-011-003). */
export interface FixOptions {
  /** Include PRs with no checks (the repo has no CI). */
  untested: boolean;
  /** Include major (and 0.x minor, and unreadable) version bumps. */
  major: boolean;
}

export const REPO_DEFAULTS: FixOptions = { untested: true, major: false };
export const FLEET_DEFAULTS: FixOptions = { untested: false, major: false };

export interface FixRequest {
  repo?: string;
  /** An owner, or undefined with no repo for the whole fleet. */
  owner?: string;
  opts: FixOptions;
}

/**
 * Reads a fix request: "fix owner/repo", "fix <owner>" or "fix fleet" (also
 * "fix all"), with optional "+untested" / "+major" anywhere in the title.
 */
export function parseFixRequest(title: string, body = ''): FixRequest | null {
  const untested = /(^|\s)\+untested\b/i.test(title);
  const major = /(^|\s)\+major\b/i.test(title);
  const repo = parseScanTarget(`${title}\n${body}`);
  if (repo) return { repo, opts: { untested: untested || REPO_DEFAULTS.untested, major } };
  const m = title.trim().match(/^fix:?\s+([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:\s|$)/i);
  if (!m) return null;
  const scope = m[1].toLowerCase() === 'fleet' || m[1].toLowerCase() === 'all' ? undefined : m[1];
  return { owner: scope, opts: { untested, major } };
}

export interface FixPlan {
  repo: string;
  scan: RepoScan;
  prs: PlannedPr[];
  /** Open alerts with a fixed version that no open Dependabot PR reaches. */
  uncovered: CveAlert[];
  /** Open alerts with no fixed version at all. */
  noFix: CveAlert[];
  /** The default branch's own CI, for the Hand-off CI issues. Absent in older plans. */
  ci?: CiHealth;
}

export interface CiHealth {
  /** The checks on the default branch's latest commit; null if they couldn't be read. */
  main: (ChecksVerdict & { sha: string }) | null;
  /** File names under .github/workflows; null if the folder couldn't be read. */
  workflows: string[] | null;
}

async function readCi(octokit: Octokit, owner: string, repo: string, branch: string): Promise<CiHealth> {
  let main: CiHealth['main'] = null;
  let workflows: CiHealth['workflows'] = null;
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/commits/{ref}', { owner, repo, ref: branch });
    main = { ...(await readChecks(octokit, owner, repo, data.sha, true)), sha: data.sha };
  } catch { /* stays null: unknown */ }
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner, repo, path: '.github/workflows', ref: branch });
    workflows = Array.isArray(data) ? data.filter((f) => f.type === 'file').map((f) => f.name) : [];
  } catch (err) {
    if ((err as { status?: number }).status === 404) workflows = [];
  }
  return { main, workflows };
}

/** Package updates from a Dependabot PR body ("Bumps [x](…) from a to b." / "Updates `x` from a to b"). */
export function parseUpdates(body: string): PackageUpdate[] {
  const out = new Map<string, PackageUpdate>();
  for (const m of body.matchAll(/Updates `([^`]+)` from (\S+?) to (\S+?)(?:\.?\s|\.?$)/gm)) out.set(m[1], { name: m[1], from: m[2], to: m[3] });
  for (const m of body.matchAll(/Bumps \[([^\]]+)\]\([^)]*\) from (\S+?) to (\S+?)\.?(?:\s|$)/gm)) {
    if (!out.has(m[1])) out.set(m[1], { name: m[1], from: m[2], to: m[3] });
  }
  return [...out.values()];
}

function majorStep(from: string, to: string): boolean {
  const parts = (v: string) => v.replace(/^v/, '').split(/[-+]/)[0].split('.').map((x) => parseInt(x, 10) || 0);
  const [a, b] = [parts(from), parts(to)];
  if (a[0] !== b[0]) return true;
  return a[0] === 0 && (a[1] ?? 0) !== (b[1] ?? 0); // 0.x: a minor step can break
}

/** The bump a Dependabot PR makes, from its parsed updates, else from "from X to Y" in its title. */
export function bumpOf(updates: PackageUpdate[], title: string): Bump {
  let pairs = updates.map((u) => [u.from, u.to] as const);
  if (!pairs.length) {
    const m = title.match(/from v?(\d[\w.+-]*) to v?(\d[\w.+-]*)/);
    if (m) pairs = [[m[1], m[2]]];
  }
  if (!pairs.length) return 'unknown';
  return pairs.some(([f, t]) => majorStep(f, t)) ? 'major' : 'minor';
}

/** Whether a planned PR goes on the rollout under these options, and if not, why. */
export function eligibility(p: PlannedPr, opts: FixOptions): { ok: boolean; why: string } {
  if (p.state === 'failing') return { ok: false, why: 'a check failed' };
  if (p.state === 'skip') return { ok: false, why: p.detail };
  if (p.bump !== 'minor' && !opts.major) return { ok: false, why: p.bump === 'major' ? 'major version: ask with +major' : 'version step unreadable: ask with +major' };
  if (p.state === 'untested' && !opts.untested) return { ok: false, why: 'no checks ran: ask with +untested' };
  return { ok: true, why: '' };
}

/** Numeric version compare on the release part (1.2.10 > 1.2.9); pre-release tags are ignored. */
export function compareVersions(a: string, b: string): number {
  const nums = (v: string) => v.replace(/^v/, '').split(/[-+]/)[0].split('.').map((x) => parseInt(x, 10) || 0);
  const x = nums(a);
  const y = nums(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export function alertsClosedBy(updates: PackageUpdate[], alerts: CveAlert[]): CveAlert[] {
  return alerts.filter((a) => a.fixedIn && updates.some((u) => u.name === a.package && compareVersions(a.fixedIn!, u.to) <= 0));
}

export function planState(verdict: { state: string; detail: string }, checksState: string): PlanState {
  if (verdict.state === 'noncompliant') return checksState === 'ready' ? 'ready' : 'untested';
  if (verdict.state === 'waiting') return 'waiting';
  if (verdict.state === 'unavailable' && verdict.detail.startsWith('failed:')) return 'failing';
  return 'skip';
}

export async function buildFixPlan(app: App, fullName: string): Promise<FixPlan> {
  const [owner, repo] = fullName.split('/');
  const scan = await scanRepo(app, fullName);
  const { octokit } = await repoOctokit(app, fullName);
  const open = await octokit.paginate('GET /repos/{owner}/{repo}/pulls', { owner, repo, state: 'open', per_page: 100 });
  const alerts = scan.alerts ?? [];
  const prs: PlannedPr[] = [];
  for (const listed of open.filter((p) => p.user?.login === 'dependabot[bot]')) {
    const pr = await getPull(octokit, owner, repo, listed.number);
    const checks = await readChecks(octokit, owner, repo, pr.head.sha, true);
    const v = judgePull(pr, scan.status.defaultBranch, checks);
    const updates = parseUpdates(pr.body ?? '');
    prs.push({
      number: listed.number, title: listed.title, url: listed.html_url,
      state: planState(v, checks.state), detail: v.state === 'noncompliant' ? checks.detail : v.detail,
      updates, closes: alertsClosedBy(updates, alerts), bump: bumpOf(updates, listed.title),
    });
  }
  prs.sort((a, b) => b.closes.length - a.closes.length || a.number - b.number);
  const covered = new Set(prs.filter((p) => p.state !== 'failing' && p.state !== 'skip').flatMap((p) => p.closes.map((a) => a.number)));
  return {
    repo: fullName, scan, prs,
    uncovered: alerts.filter((a) => a.fixedIn && !covered.has(a.number)),
    noFix: alerts.filter((a) => !a.fixedIn),
    ci: await readCi(octokit, owner, repo, scan.status.defaultBranch),
  };
}

/** The PRs to put on the rollout: everything that may be merged, with a note the owner sees. */
export function rolloutTargets(plan: FixPlan, opts: FixOptions = REPO_DEFAULTS): { targets: string[]; notes: Record<string, string> } {
  const targets: string[] = [];
  const notes: Record<string, string> = {};
  for (const p of plan.prs.filter((x) => eligibility(x, opts).ok)) {
    const t = `${plan.repo}#${p.number}`;
    targets.push(t);
    const label = { ready: '🟢 checks passed', untested: '🟡 untested: no checks ran', waiting: '⏳ waiting (conflict or checks running)' }[p.state as 'ready' | 'untested' | 'waiting'];
    notes[t] = `${label} · closes ${p.closes.length} alert${p.closes.length === 1 ? '' : 's'} · ${p.title.replace(/\|/g, '/')}`;
  }
  return { targets, notes };
}

const STATE_TEXT: Record<PlanState, string> = {
  ready: '🟢 ready', untested: '🟡 untested', waiting: '⏳ waiting', failing: '🔴 failing', skip: '— skipped',
};

/** @param rolloutRef how to name the rollout issue (e.g. "#17"), or undefined when there's nothing to merge. */
export function renderFixPlan(plan: FixPlan, rolloutRef?: string, opts: FixOptions = REPO_DEFAULTS): string {
  const s = plan.scan;
  const alerts = s.alerts?.length ?? 0;
  const willClose = new Set(plan.prs.filter((p) => eligibility(p, opts).ok).flatMap((p) => p.closes.map((a) => a.number))).size;
  const out: string[] = [];
  out.push(`## git-steer fix plan: [${plan.repo}](${s.status.url})`, '');
  out.push(verdict(s), '');
  if (s.alerts === null) {
    out.push('Dependabot alerts aren\'t readable for this repo, so which alerts each PR closes is unknown.', '');
  } else {
    out.push(`Merging the PRs below would close **${willClose} of ${alerts}** open Dependabot alerts.`, '');
  }

  if (plan.prs.length) {
    out.push(`### Dependabot PRs (${plan.prs.length})`, '');
    out.push('| PR | State | Checks | Closes | Updates | On rollout |', '|---|---|---|---|---|---|');
    for (const p of plan.prs) {
      const ups = p.updates.map((u) => `${u.name} ${u.from} → ${u.to}`).join('<br>') || '—';
      const e = eligibility(p, opts);
      out.push(`| [#${p.number}](${p.url}) ${p.title.replace(/\|/g, '/')} | ${STATE_TEXT[p.state]} | ${p.detail.replace(/\|/g, '/')} | ${p.closes.length} | ${ups} | ${e.ok ? '✅' : `— ${e.why}`} |`);
    }
    out.push('', '🟢 checks passed · 🟡 no checks ran (the repo has no CI): merging is your call · ⏳ in conflict or checks running: merged once Dependabot rebases · 🔴 a check failed: never merged', '');
  } else {
    out.push('### Dependabot PRs', '', 'No open Dependabot PRs.', '');
  }

  if (plan.uncovered.length) {
    out.push(`### Fixable, but no Dependabot PR yet (${plan.uncovered.length})`, '');
    const byPkg = new Map<string, CveAlert[]>();
    for (const a of plan.uncovered) byPkg.set(a.package, [...(byPkg.get(a.package) ?? []), a]);
    for (const [pkg, list] of byPkg) out.push(`- **${pkg}**: ${list.length} alert(s), fixed in ${[...new Set(list.map((a) => a.fixedIn))].join(', ')}`);
    out.push('', 'Dependabot may open these after the merges above, or they need a manual upgrade: a candidate for 🤖 Hand off to Copilot.', '');
  }
  if (plan.noFix.length) {
    out.push(`### No fix exists (${plan.noFix.length})`, '');
    for (const a of plan.noFix) out.push(`- ${a.severity} · **${a.package}** · [${a.ghsa}](${a.url})${a.cve ? ` · ${a.cve}` : ''}`);
    out.push('', 'Remove or replace the dependency (🤖 Hand off to Copilot), or accept the risk with a reason (✋ Accept risk).', '');
  }

  out.push('### Next', '');
  if (rolloutRef) {
    out.push(`Rollout ${rolloutRef} lists the PRs git-steer may merge. **Delete the line of any PR you don't want merged**, then add the \`approved\` label there. git-steer merges one PR per step, re-checking each just before merging, and never merges one whose checks failed.`);
  } else {
    out.push('Nothing to merge right now.');
  }
  out.push('', '---', '', 'Read-only plan by git-steer. Nothing has been changed yet.');
  return out.join('\n') + '\n';
}
