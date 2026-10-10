/**
 * Fix a repo: the plan (ADR-011). Read-only, through the reporter App.
 *
 * Lists the repo's open Dependabot PRs, each with its checks and the open
 * alerts it would close, and what no PR covers. The ready, untested and
 * waiting PRs become the targets of a merge-dependabot-pr rollout the owner
 * approves; failing ones are listed and never merged (C-011-003).
 */

import type { App } from 'octokit';
import { judgePull, readChecks } from '../rollout/changes/merge-dependabot-pr.js';
import type { PullLike } from '../rollout/changes/merge-dependabot-pr.js';
import { repoOctokit, scanRepo } from './collect.js';
import { verdict } from './scan.js';
import type { CveAlert, RepoScan } from './types.js';

export type PlanState = 'ready' | 'untested' | 'waiting' | 'failing' | 'skip';

export interface PackageUpdate { name: string; from: string; to: string }

export interface PlannedPr {
  number: number;
  title: string;
  url: string;
  state: PlanState;
  detail: string;
  updates: PackageUpdate[];
  closes: CveAlert[];
}

export interface FixPlan {
  repo: string;
  scan: RepoScan;
  prs: PlannedPr[];
  /** Open alerts with a fixed version that no open Dependabot PR reaches. */
  uncovered: CveAlert[];
  /** Open alerts with no fixed version at all. */
  noFix: CveAlert[];
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
    const { data: pr } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner, repo, pull_number: listed.number });
    const checks = await readChecks(octokit, owner, repo, pr.head.sha);
    const v = judgePull(pr as unknown as PullLike, scan.status.defaultBranch, checks);
    const updates = parseUpdates(pr.body ?? '');
    prs.push({
      number: pr.number, title: pr.title, url: pr.html_url,
      state: planState(v, checks.state), detail: v.state === 'noncompliant' ? checks.detail : v.detail,
      updates, closes: alertsClosedBy(updates, alerts),
    });
  }
  prs.sort((a, b) => b.closes.length - a.closes.length || a.number - b.number);
  const covered = new Set(prs.filter((p) => p.state !== 'failing' && p.state !== 'skip').flatMap((p) => p.closes.map((a) => a.number)));
  return {
    repo: fullName, scan, prs,
    uncovered: alerts.filter((a) => a.fixedIn && !covered.has(a.number)),
    noFix: alerts.filter((a) => !a.fixedIn),
  };
}

/** The PRs to put on the rollout: everything that may be merged, with a note the owner sees. */
export function rolloutTargets(plan: FixPlan): { targets: string[]; notes: Record<string, string> } {
  const targets: string[] = [];
  const notes: Record<string, string> = {};
  for (const p of plan.prs.filter((x) => x.state === 'ready' || x.state === 'untested' || x.state === 'waiting')) {
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
export function renderFixPlan(plan: FixPlan, rolloutRef?: string): string {
  const s = plan.scan;
  const alerts = s.alerts?.length ?? 0;
  const willClose = new Set(plan.prs.filter((p) => p.state !== 'failing' && p.state !== 'skip').flatMap((p) => p.closes.map((a) => a.number))).size;
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
    out.push('| PR | State | Checks | Closes | Updates |', '|---|---|---|---|---|');
    for (const p of plan.prs) {
      const ups = p.updates.map((u) => `${u.name} ${u.from} → ${u.to}`).join('<br>') || '—';
      out.push(`| [#${p.number}](${p.url}) ${p.title.replace(/\|/g, '/')} | ${STATE_TEXT[p.state]} | ${p.detail.replace(/\|/g, '/')} | ${p.closes.length} | ${ups} |`);
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
