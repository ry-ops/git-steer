import { describe, it, expect } from 'vitest';
import { alertsClosedBy, compareVersions, parseUpdates, planState, renderFixPlan, rolloutTargets } from '../fleet/fix.js';
import type { FixPlan } from '../fleet/fix.js';
import { judgeChecks, judgePull, parsePullTarget } from '../rollout/changes/merge-dependabot-pr.js';
import type { PullLike } from '../rollout/changes/merge-dependabot-pr.js';
import { parseRolloutIssue, recordResult, renderRolloutIssue } from '../rollout/issue.js';
import { applyToTarget } from '../rollout/apply.js';
import type { Octokit } from 'octokit';
import type { CveAlert, RepoScan } from '../fleet/types.js';

const alert = (over: Partial<CveAlert>): CveAlert => ({
  number: 1, ghsa: 'GHSA-x', cve: null, package: 'hono', ecosystem: 'npm', manifest: 'package-lock.json',
  severity: 'high', fixedIn: '4.12.4', url: 'https://x', ...over,
});

describe('Dependabot PR bodies', () => {
  it('reads single and grouped updates (git-fabric/gateway #9, #10)', () => {
    expect(parseUpdates('Bumps [hono](https://github.com/honojs/hono) from 4.12.0 to 4.13.13.\n- [Release notes]'))
      .toEqual([{ name: 'hono', from: '4.12.0', to: '4.13.13' }]);
    const grouped = 'Bumps [ip-address](https://x) and [express-rate-limit](https://y). These dependencies needed to be updated together.\nUpdates `ip-address` from 10.0.1 to 10.7.3\nDetails\nUpdates `express-rate-limit` from 8.2.1 to 8.7.0\n';
    expect(parseUpdates(grouped)).toEqual([
      { name: 'ip-address', from: '10.0.1', to: '10.7.3' },
      { name: 'express-rate-limit', from: '8.2.1', to: '8.7.0' },
    ]);
  });

  it('compares versions numerically', () => {
    expect(compareVersions('4.12.34', '4.13.13')).toBeLessThan(0);
    expect(compareVersions('4.13.13', '4.13.7')).toBeGreaterThan(0);
    expect(compareVersions('v10.7.1', '10.7.3')).toBeLessThan(0);
    expect(compareVersions('2.0.0-beta.1', '2.0.0')).toBe(0);
  });

  it('maps a PR to the alerts it closes, and not to ones it does not reach', () => {
    const alerts = [alert({ number: 1, fixedIn: '4.12.4' }), alert({ number: 2, fixedIn: '4.13.7' }), alert({ number: 3, fixedIn: '4.14.0' }),
      alert({ number: 4, package: 'request', fixedIn: null })];
    expect(alertsClosedBy([{ name: 'hono', from: '4.12.0', to: '4.13.13' }], alerts).map((a) => a.number)).toEqual([1, 2]);
  });
});

describe('merge-dependabot-pr', () => {
  const pr = (over: Partial<PullLike> = {}): PullLike => ({
    state: 'open', merged: false, mergeable: true, mergeable_state: 'clean',
    user: { login: 'dependabot[bot]' }, base: { ref: 'main' }, head: { sha: 'abcdef1234' }, ...over,
  });
  const ready = judgeChecks([{ name: 'test', status: 'completed', conclusion: 'success' }], []);
  const untested = judgeChecks([{ name: 'CodeQL', status: 'completed', conclusion: 'neutral' }], []);

  it('parses PR targets', () => {
    expect(parsePullTarget('git-fabric/gateway#9')).toEqual({ owner: 'git-fabric', repo: 'gateway', number: 9 });
    expect(() => parsePullTarget('git-fabric/gateway')).toThrow();
  });

  it('judges checks: neutral CodeQL alone is untested, any failure is failing', () => {
    expect(untested.state).toBe('untested');
    expect(ready).toEqual({ state: 'ready', detail: 'passed: test' });
    expect(judgeChecks([{ name: 'ci', status: 'completed', conclusion: 'failure' }, { name: 'x', status: 'completed', conclusion: 'success' }], []).state).toBe('failing');
    expect(judgeChecks([], [{ context: 'ci/legacy', state: 'error' }]).state).toBe('failing');
    expect(judgeChecks([{ name: 'ci', status: 'in_progress', conclusion: null }], []).state).toBe('running');
  });

  it('merges only open Dependabot PRs into the default branch, never failing ones (C-011-003)', () => {
    expect(judgePull(pr(), 'main', ready).state).toBe('noncompliant');
    expect(judgePull(pr(), 'main', untested).state).toBe('noncompliant');
    expect(judgePull(pr({ merged: true, state: 'closed' }), 'main', ready).state).toBe('compliant');
    expect(judgePull(pr({ state: 'closed' }), 'main', ready).state).toBe('unavailable');
    expect(judgePull(pr({ user: { login: 'someone' } }), 'main', ready)).toMatchObject({ state: 'unavailable', detail: 'not a Dependabot PR (someone)' });
    expect(judgePull(pr({ base: { ref: 'dev' } }), 'main', ready).state).toBe('unavailable');
    expect(judgePull(pr(), 'main', { state: 'failing', detail: 'failed: ci' }).state).toBe('unavailable');
  });

  it('waits on conflicts, unknown mergeability and running checks', () => {
    expect(judgePull(pr({ mergeable: null }), 'main', ready).state).toBe('waiting');
    expect(judgePull(pr({ mergeable: false, mergeable_state: 'dirty' }), 'main', ready).state).toBe('waiting');
    expect(judgePull(pr(), 'main', { state: 'running', detail: 'running: ci' }).state).toBe('waiting');
  });

  it('records waiting without ticking, pausing or counting as a write', async () => {
    const r = await applyToTarget({ id: 'merge-dependabot-pr', target: 'pr', summary: '', check: async () => ({ state: 'waiting', detail: 'in conflict' }), apply: async () => { throw new Error('must not write'); } },
      {} as Octokit, 7, 'git-fabric/gateway#9');
    expect(r.outcome).toBe('waiting');
    const body = recordResult(renderRolloutIssue({ change: 'merge-dependabot-pr', summary: 's', targets: ['git-fabric/gateway#9'], notes: { 'git-fabric/gateway#9': '🟡 untested · closes 35 alerts · bump hono' }, startedBy: 'ry-ops' }).body, r);
    const item = parseRolloutIssue(body)!.items[0];
    expect(item).toMatchObject({ target: 'git-fabric/gateway#9', done: false, wroteAt: null });
    expect(item.note).toContain('⏳ waiting: in conflict');
  });

  it('keeps PR targets and their notes through the rollout issue', () => {
    const { body } = renderRolloutIssue({ change: 'merge-dependabot-pr', summary: 's', targets: ['a/b#1', 'a/b#2'], notes: { 'a/b#1': '🟢 checks passed' }, startedBy: 'ry-ops' });
    expect(body).toContain('- [ ] a/b#1 — 🟢 checks passed');
    expect(parseRolloutIssue(body)!.items.map((i) => [i.target, i.done, i.wroteAt])).toEqual([['a/b#1', false, null], ['a/b#2', false, null]]);
  });
});

describe('fix plan', () => {
  const scan = (alerts: CveAlert[]): RepoScan => ({
    generatedAt: '2026-10-10T16:00:00Z', app: 'git-steer-reporter', archived: false, alerts,
    status: {
      repo: 'git-fabric/gateway', owner: 'git-fabric', private: false, defaultBranch: 'main', url: 'https://github.com/git-fabric/gateway',
      coverage: { dependabotAlerts: 'on', dependabotSecurityUpdates: 'on', codeScanning: 'on', secretScanning: 'on', pushProtection: 'on', branchProtection: 'on' },
      findings: { dependabot: { critical: 0, high: alerts.length, medium: 0, low: 0 }, codeScanning: { critical: 0, high: 0, medium: 0, low: 0 }, secretScanning: 0, noPatch: [], staleDependabotPrs: [], undocumentedDismissals: [] },
      config: 'absent', errors: [],
    },
  });

  it('maps plan states', () => {
    expect(planState({ state: 'noncompliant', detail: '' }, 'ready')).toBe('ready');
    expect(planState({ state: 'noncompliant', detail: '' }, 'untested')).toBe('untested');
    expect(planState({ state: 'waiting', detail: '' }, 'running')).toBe('waiting');
    expect(planState({ state: 'unavailable', detail: 'failed: ci' }, 'failing')).toBe('failing');
    expect(planState({ state: 'unavailable', detail: 'closed without merging' }, 'untested')).toBe('skip');
  });

  it('puts mergeable PRs on the rollout, lists failing ones and what no PR covers', () => {
    const a1 = alert({ number: 1 });
    const a2 = alert({ number: 2, package: 'tar', fixedIn: '7.5.19' });
    const a3 = alert({ number: 3, package: 'request', fixedIn: null, ghsa: 'GHSA-p8p7' });
    const plan: FixPlan = {
      repo: 'git-fabric/gateway', scan: scan([a1, a2, a3]),
      prs: [
        { number: 9, title: 'bump hono', url: 'https://x/9', state: 'untested', detail: 'no checks ran', updates: [{ name: 'hono', from: '4.12.0', to: '4.13.13' }], closes: [a1] },
        { number: 5, title: 'Patch 30 vulns', url: 'https://x/5', state: 'failing', detail: 'failed: ci', updates: [], closes: [] },
      ],
      uncovered: [a2], noFix: [a3],
    };
    const { targets, notes } = rolloutTargets(plan);
    expect(targets).toEqual(['git-fabric/gateway#9']);
    expect(notes['git-fabric/gateway#9']).toBe('🟡 untested: no checks ran · closes 1 alert · bump hono');
    const md = renderFixPlan(plan, '#20');
    expect(md).toContain('would close **1 of 3**');
    expect(md).toContain('| 🔴 failing |');
    expect(md).toContain('- **tar**: 1 alert(s), fixed in 7.5.19');
    expect(md).toContain('**request** · [GHSA-p8p7]');
    expect(md).toContain('Rollout #20 lists the PRs');
    expect(renderFixPlan({ ...plan, prs: [] })).toContain('Nothing to merge right now.');
  });
});
