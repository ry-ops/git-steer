import { describe, it, expect } from 'vitest';
import { bumpOf, eligibility, FLEET_DEFAULTS, parseFixRequest, REPO_DEFAULTS } from '../fleet/fix.js';
import type { FixPlan, PlannedPr } from '../fleet/fix.js';
import { fleetRolloutTargets, renderFleetFixPlan } from '../fleet/fleetfix.js';
import type { FleetFixPlan } from '../fleet/fleetfix.js';
import { judgePull } from '../rollout/changes/merge-dependabot-pr.js';
import { parseRolloutIssue, recordResult, renderRolloutIssue } from '../rollout/issue.js';
import { planStep } from '../rollout/plan.js';
import type { CveAlert } from '../fleet/types.js';

const alert = (n: number): CveAlert => ({ number: n, ghsa: '', cve: null, package: 'p', ecosystem: 'npm', manifest: 'package-lock.json', severity: 'high', fixedIn: '1.0.0', url: '' });
const pr = (n: number, over: Partial<PlannedPr> = {}): PlannedPr => ({
  number: n, title: `bump x from 1.0.0 to 1.1.${n}`, url: '', state: 'ready', detail: '', updates: [], closes: [], bump: 'minor', ...over,
});
function plan(repo: string, prs: PlannedPr[]): FixPlan {
  return {
    repo, prs, uncovered: [], noFix: [],
    scan: {
      generatedAt: '', app: '', archived: false, alerts: [],
      status: {
        repo, owner: repo.split('/')[0], private: false, defaultBranch: 'main', url: '',
        coverage: { dependabotAlerts: 'on', dependabotSecurityUpdates: 'on', codeScanning: 'on', secretScanning: 'on', pushProtection: 'on', branchProtection: 'on' },
        findings: { dependabot: null, codeScanning: null, secretScanning: 0, noPatch: [], staleDependabotPrs: [], undocumentedDismissals: [] },
        config: 'absent', errors: [],
      },
    },
  };
}

describe('fix requests', () => {
  it('reads repo, owner and fleet scopes with their defaults and flags', () => {
    expect(parseFixRequest('fix git-fabric/gateway')).toEqual({ repo: 'git-fabric/gateway', opts: REPO_DEFAULTS });
    expect(parseFixRequest('fix fleet')).toEqual({ owner: undefined, opts: FLEET_DEFAULTS });
    expect(parseFixRequest('Fix all +untested')).toEqual({ owner: undefined, opts: { untested: true, major: false } });
    expect(parseFixRequest('fix fabric-forge +major')).toEqual({ owner: 'fabric-forge', opts: { untested: false, major: true } });
    expect(parseFixRequest('fix')).toBeNull();
  });
});

describe('version steps', () => {
  it('treats a major step, a 0.x minor step and an unreadable title as not minor', () => {
    expect(bumpOf([{ name: 'a', from: '4.12.0', to: '4.13.13' }], '')).toBe('minor');
    expect(bumpOf([{ name: 'a', from: '4.1.0', to: '5.0.0' }], '')).toBe('major');
    expect(bumpOf([{ name: 'a', from: '0.21.0', to: '0.22.0' }], '')).toBe('major');
    expect(bumpOf([{ name: 'a', from: '0.21.0', to: '0.21.3' }], '')).toBe('minor');
    expect(bumpOf([], 'chore(deps): bump vitest from 4.0.18 to 4.1.11')).toBe('minor');
    expect(bumpOf([], 'chore(deps): bump the npm group')).toBe('unknown');
  });

  it('holds untested, major and failing PRs unless asked', () => {
    expect(eligibility(pr(1, { state: 'untested' }), FLEET_DEFAULTS)).toEqual({ ok: false, why: 'no checks ran: ask with +untested' });
    expect(eligibility(pr(1, { state: 'untested' }), REPO_DEFAULTS).ok).toBe(true);
    expect(eligibility(pr(1, { bump: 'major' }), { untested: true, major: false }).ok).toBe(false);
    expect(eligibility(pr(1, { bump: 'major' }), { untested: true, major: true }).ok).toBe(true);
    expect(eligibility(pr(1, { state: 'failing' }), { untested: true, major: true }).ok).toBe(false);
    expect(eligibility(pr(1, { state: 'waiting' }), FLEET_DEFAULTS).ok).toBe(true);
  });
});

describe('fleet rollout', () => {
  const fleet: FleetFixPlan = {
    scope: 'fleet', errors: [],
    plans: [
      plan('a/one', [pr(1, { closes: [alert(1)] }), pr(2, { closes: [alert(2), alert(3)] }), pr(3)]),
      plan('b/two', [pr(7, { closes: [alert(9), alert(8), alert(7)] }), pr(8, { state: 'untested' }), pr(9, { state: 'failing' })]),
    ],
  };

  it('interleaves repos, most useful first, and keeps held PRs off', () => {
    // Both repos close 3 alerts, so the tie goes alphabetically; within a repo, most alerts first.
    const { targets, held } = fleetRolloutTargets(fleet, FLEET_DEFAULTS);
    expect(targets).toEqual(['a/one#2', 'b/two#7', 'a/one#1', 'a/one#3']);
    expect(held).toBe(0);
    expect(fleetRolloutTargets(fleet, { untested: true, major: false }).targets).toEqual(['a/one#2', 'b/two#7', 'a/one#1', 'b/two#8', 'a/one#3']);
  });

  it('caps the rollout and says how many are held back', () => {
    const r = fleetRolloutTargets(fleet, FLEET_DEFAULTS, 2);
    expect(r.targets).toEqual(['a/one#2', 'b/two#7']);
    expect(r.held).toBe(2);
  });

  it('renders a per-repo summary with what was held and why', () => {
    const md = renderFleetFixPlan(fleet, FLEET_DEFAULTS, '#30', 4, 0);
    expect(md).toContain('**6** open Dependabot PRs in **2** repos. **4** go on the rollout (options: none)');
    expect(md).toContain('| b/two | 0 | 3 | 1 | 3 | 1 |  | 1 |');
    expect(md).toContain('Rollout #30 lists every PR');
    expect(md).toContain('a PR with no passing check is skipped');
  });
});

describe('merge rules at merge time', () => {
  const open = { state: 'open', merged: false, mergeable: true, mergeable_state: 'clean', user: { login: 'dependabot[bot]' }, base: { ref: 'main' }, head: { sha: 'abc' } };
  it('the tested-only change skips a PR with no checks', () => {
    expect(judgePull(open, 'main', { state: 'untested', detail: 'no checks ran' }).state).toBe('noncompliant');
    expect(judgePull(open, 'main', { state: 'untested', detail: 'no checks ran' }, true).state).toBe('unavailable');
    expect(judgePull(open, 'main', { state: 'ready', detail: 'passed: ci' }, true).state).toBe('noncompliant');
  });

  it('labels a skipped target as skipped, not as a plan limit', () => {
    const body = renderRolloutIssue({ change: 'merge-dependabot-pr', summary: '', targets: ['a/b#1'], startedBy: 'x' }).body;
    const out = recordResult(body, { issue: 1, change: 'merge-dependabot-pr', target: 'a/b#1', outcome: 'unavailable', before: 'closed without merging', after: 'closed without merging', at: '2026-10-10T18:57:00Z' });
    expect(out).toContain('- [x] a/b#1 — — skipped: closed without merging');
    expect(out).not.toContain('not available on this plan');
  });
});

describe('waiting back-off', () => {
  it('does not spend the hour on targets found waiting in the last 30 minutes', () => {
    let body = renderRolloutIssue({ change: 'merge-dependabot-pr', summary: '', targets: ['a/b#1', 'a/b#2'], startedBy: 'x' }).body;
    body = recordResult(body, { issue: 5, change: 'merge-dependabot-pr', target: 'a/b#1', outcome: 'waiting', before: 'in conflict', after: 'in conflict', at: '2026-10-10T18:40:00Z' });
    expect(parseRolloutIssue(body)!.items[0].waitingAt?.toISOString()).toBe('2026-10-10T18:40:00.000Z');
    const issue = { number: 5, open: true, body, labels: ['approved'], openedByGitSteer: true, approvedByOwner: true };
    expect(planStep([issue], ['merge-dependabot-pr'], new Date('2026-10-10T18:50:00Z')).items.map((i) => i.target)).toEqual(['a/b#2']);
    expect(planStep([issue], ['merge-dependabot-pr'], new Date('2026-10-10T19:15:00Z')).items.map((i) => i.target)).toEqual(['a/b#1', 'a/b#2']);
  });
});
