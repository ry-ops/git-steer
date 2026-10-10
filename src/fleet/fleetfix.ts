/**
 * Fix the fleet (ADR-011): one plan and one rollout across many repos.
 *
 * "fix fleet" covers every repo the reporter App can see; "fix <owner>" one
 * account. Read-only. Only repos with open Dependabot PRs are planned. The
 * rollout interleaves repos, so consecutive merges land in different repos
 * (merging two PRs in one repo usually puts the next in conflict until
 * Dependabot rebases), with each repo's most useful PRs first.
 */

import type { App } from 'octokit';
import pLimit from 'p-limit';
import { buildFixPlan, eligibility } from './fix.js';
import type { FixOptions, FixPlan } from './fix.js';

export const MAX_FLEET_TARGETS = 150;
const REPO_CONCURRENCY = 3;

export interface FleetFixPlan {
  scope: string;
  plans: FixPlan[];
  errors: { repo: string; message: string }[];
}

interface Repo { full_name: string; archived: boolean }

export async function buildFleetFixPlan(app: App, owner?: string): Promise<FleetFixPlan> {
  const scope = owner ?? 'fleet';
  const candidates: string[] = [];
  let seenOwner = false;
  for await (const { octokit, installation } of app.eachInstallation.iterator()) {
    const account = (installation.account as { login?: string } | null)?.login ?? '';
    if (owner && account.toLowerCase() !== owner.toLowerCase()) continue;
    seenOwner = true;
    if (installation.suspended_at) continue;
    const inst = octokit; // already authenticated as this installation
    const repos = (await inst.paginate('GET /installation/repositories', { per_page: 100 })) as unknown as Repo[];
    for (const r of repos.filter((x) => !x.archived)) {
      const [o, n] = r.full_name.split('/');
      const pulls = await inst.paginate('GET /repos/{owner}/{repo}/pulls', { owner: o, repo: n, state: 'open', per_page: 100 });
      if (pulls.some((p) => p.user?.login === 'dependabot[bot]')) candidates.push(r.full_name);
    }
  }
  if (owner && !seenOwner) throw new Error(`git-steer-reporter isn't installed on ${owner}.`);

  const limit = pLimit(REPO_CONCURRENCY);
  const errors: FleetFixPlan['errors'] = [];
  const plans = (await Promise.all(candidates.sort().map((repo) => limit(async () => {
    try {
      return await buildFixPlan(app, repo);
    } catch (err) {
      errors.push({ repo, message: err instanceof Error ? err.message : String(err) });
      return null;
    }
  })))).filter((p): p is FixPlan => p !== null);
  return { scope, plans, errors };
}

/**
 * The rollout's targets: each repo's eligible PRs, most alerts closed first,
 * taken round-robin across repos (repos with the most to close first).
 */
export function fleetRolloutTargets(fleet: FleetFixPlan, opts: FixOptions, max = MAX_FLEET_TARGETS): {
  targets: string[]; notes: Record<string, string>; held: number;
} {
  const queues = fleet.plans
    .map((plan) => ({
      plan,
      prs: plan.prs.filter((p) => eligibility(p, opts).ok).sort((a, b) => b.closes.length - a.closes.length || a.number - b.number),
    }))
    .filter((q) => q.prs.length)
    .sort((a, b) => b.prs.reduce((n, p) => n + p.closes.length, 0) - a.prs.reduce((n, p) => n + p.closes.length, 0) || a.plan.repo.localeCompare(b.plan.repo));
  const targets: string[] = [];
  const notes: Record<string, string> = {};
  const total = queues.reduce((n, q) => n + q.prs.length, 0);
  for (let i = 0; targets.length < max && queues.some((q) => q.prs.length > i); i++) {
    for (const q of queues) {
      const p = q.prs[i];
      if (!p || targets.length >= max) continue;
      const t = `${q.plan.repo}#${p.number}`;
      targets.push(t);
      const label = { ready: '🟢 checks passed', untested: '🟡 untested', waiting: '⏳ waiting' }[p.state as 'ready' | 'untested' | 'waiting'];
      notes[t] = `${label} · closes ${p.closes.length} · ${p.title.replace(/\|/g, '/').slice(0, 90)}`;
    }
  }
  return { targets, notes, held: total - targets.length };
}

export function renderFleetFixPlan(fleet: FleetFixPlan, opts: FixOptions, rolloutRef: string | undefined, onRollout: number, heldByCap: number): string {
  const rows = fleet.plans.map((plan) => {
    const prs = plan.prs;
    const on = prs.filter((p) => eligibility(p, opts).ok);
    const n = (f: (p: (typeof prs)[number]) => boolean) => prs.filter(f).length;
    const closes = new Set(on.flatMap((p) => p.closes.map((a) => a.number))).size;
    return {
      repo: plan.repo, alerts: plan.scan.alerts?.length ?? null, prs: prs.length, on: on.length, closes,
      untestedHeld: n((p) => p.state === 'untested' && !eligibility(p, opts).ok && p.bump === 'minor'),
      majorHeld: n((p) => p.bump !== 'minor' && p.state !== 'failing' && !opts.major),
      failing: n((p) => p.state === 'failing'),
    };
  }).sort((a, b) => b.closes - a.closes || b.on - a.on || a.repo.localeCompare(b.repo));
  const sum = (k: 'prs' | 'on' | 'closes' | 'untestedHeld' | 'majorHeld' | 'failing') => rows.reduce((n, r) => n + r[k], 0);
  const flags = [opts.untested ? '+untested' : '', opts.major ? '+major' : ''].filter(Boolean).join(' ') || 'none';

  const out = [`## git-steer fix plan: ${fleet.scope === 'fleet' ? 'the fleet' : fleet.scope}`, ''];
  out.push(`**${sum('prs')}** open Dependabot PRs in **${rows.length}** repos. **${onRollout}** go on the rollout (options: ${flags}); merging them closes **${sum('closes')}** open alerts.`, '');
  out.push('| Repo | Open alerts | Dependabot PRs | On rollout | Closes | Held: untested | Held: major | Failing |', '|---|---|---|---|---|---|---|---|');
  for (const r of rows) out.push(`| ${r.repo} | ${r.alerts ?? '?'} | ${r.prs} | ${r.on} | ${r.closes} | ${r.untestedHeld || ''} | ${r.majorHeld || ''} | ${r.failing || ''} |`);
  out.push(`| **Total** | | **${sum('prs')}** | **${sum('on')}** | **${sum('closes')}** | ${sum('untestedHeld')} | ${sum('majorHeld')} | ${sum('failing')} |`, '');
  out.push('- **Held: untested**: no checks ran (the repo has no CI). Ask again with `+untested` to include them, or fix them per repo with `fix owner/repo`.');
  out.push('- **Held: major**: a major (or 0.x minor) version step, or one git-steer couldn\'t read. Review per repo; `+major` includes them.');
  out.push('- **Failing**: a check failed. Never merged. These usually need a code change: a candidate for 🤖 Hand off.');
  if (heldByCap) out.push(`- **${heldByCap}** more eligible PRs are held back (at most ${MAX_FLEET_TARGETS} per rollout). Ask again when this one is done.`);
  if (fleet.errors.length) out.push('', `**Couldn't plan ${fleet.errors.length} repo(s):** ${fleet.errors.map((e) => `${e.repo} (${e.message})`).join('; ')}`);
  out.push('', '### Next', '');
  out.push(rolloutRef
    ? `Rollout ${rolloutRef} lists every PR git-steer may merge, interleaved across repos. Delete any line you don't want, then add the \`approved\` label. git-steer merges at most 5 per hour, one per job, re-checking each just before merging${opts.untested ? '' : '; a PR with no passing check is skipped even if it was waiting when planned'}.`
    : 'Nothing to merge under these options.');
  out.push('', '---', '', 'Read-only plan by git-steer. Nothing has been changed yet.');
  return out.join('\n') + '\n';
}
