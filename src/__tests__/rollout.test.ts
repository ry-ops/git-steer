import { describe, it, expect } from 'vitest';
import type { Octokit } from 'octokit';
import { desiredRuleset, evaluateRuleset } from '../rollout/changes/default-branch-ruleset.js';
import { analysisState, evaluateSettings, securitySettings } from '../rollout/changes/security-settings.js';
import { evaluateSponsorships, sponsorships } from '../rollout/changes/sponsorships.js';
import { parseRolloutIssue, recordResult, remaining, renderRolloutIssue } from '../rollout/issue.js';
import { planStep, recentWrites } from '../rollout/plan.js';
import type { RolloutIssue } from '../rollout/plan.js';
import { applyToTarget } from '../rollout/apply.js';
import type { Change, CheckResult } from '../rollout/types.js';

const body = (targets: string[]) =>
  renderRolloutIssue({ change: 'default-branch-ruleset', summary: 'Ruleset.', targets, startedBy: 'ry-ops' }).body;

describe('rollout issue', () => {
  it('round-trips change and targets', () => {
    const r = parseRolloutIssue(body(['TAEM-DEV/adrs', 'ry-ops/blog', 'git-fabric']));
    expect(r?.change).toBe('default-branch-ruleset');
    expect(r?.items.map((i) => i.target)).toEqual(['TAEM-DEV/adrs', 'ry-ops/blog', 'git-fabric']);
    expect(r?.items.every((i) => !i.done)).toBe(true);
  });

  it('ignores issues without the marker', () => {
    expect(parseRolloutIssue('- [ ] TAEM-DEV/adrs')).toBeNull();
  });

  it('ticks a done target and leaves a failed one open for retry', () => {
    let b = body(['a/one', 'a/two']);
    b = recordResult(b, { issue: 1, change: 'x', target: 'a/one', outcome: 'applied', before: 'no ruleset', after: 'ruleset #9 active', at: '2026-10-04T18:00:00Z', runUrl: 'https://run/1' });
    b = recordResult(b, { issue: 1, change: 'x', target: 'a/two', outcome: 'failed', before: 'no ruleset', after: 'apply error 422', at: '2026-10-04T18:01:00Z' });
    const r = parseRolloutIssue(b)!;
    expect(r.items[0]).toMatchObject({ target: 'a/one', done: true });
    expect(r.items[0].note).toContain('✅ applied: no ruleset → ruleset #9 active');
    expect(r.items[0].note).toContain('[run](https://run/1)');
    expect(r.items[1]).toMatchObject({ target: 'a/two', done: false });
    expect(r.items[1].note).toContain('❌ failed');
    expect(remaining(r).map((i) => i.target)).toEqual(['a/two']);
  });
});

describe('planStep', () => {
  const issue = (n: number, targets: string[], over: Partial<RolloutIssue> = {}): RolloutIssue => ({
    number: n, open: true, body: body(targets), labels: ['git-steer-rollout', 'approved'], openedByGitSteer: true, approvedByOwner: true, ...over,
  });
  const known = ['default-branch-ruleset'];

  it('takes at most the budget, oldest rollout first', () => {
    const { items } = planStep([issue(9, ['b/1', 'b/2']), issue(3, ['a/1', 'a/2', 'a/3', 'a/4'])], known);
    expect(items.map((i) => i.target)).toEqual(['a/1', 'a/2', 'a/3', 'a/4', 'b/1']);
  });

  it('only continues approved, unpaused rollouts the start workflow opened', () => {
    const { items, skipped } = planStep([
      issue(1, ['a/1'], { approvedByOwner: false }),
      issue(2, ['b/1'], { labels: ['git-steer-rollout', 'approved', 'paused'] }),
      issue(3, ['c/1'], { openedByGitSteer: false }),
      issue(4, ['d/1']),
    ], known);
    expect(items.map((i) => i.target)).toEqual(['d/1']);
    expect(skipped.map((s) => s.reason)).toEqual(['waiting for approval', 'paused', 'not opened by the start workflow']);
  });

  it('counts writes from the last hour against the budget, from any rollout (C-010-003)', () => {
    const now = new Date('2026-10-04T19:00:00Z');
    let done = body(['x/1', 'x/2', 'x/3', 'x/4']);
    for (const [t, at] of [['x/1', '2026-10-04T18:20:00Z'], ['x/2', '2026-10-04T18:21:00Z'], ['x/3', '2026-10-04T17:30:00Z']] as const) {
      done = recordResult(done, { issue: 1, change: 'x', target: t, outcome: 'applied', before: 'a', after: 'b', at });
    }
    done = recordResult(done, { issue: 1, change: 'x', target: 'x/4', outcome: 'already-compliant', before: 'ok', after: 'ok', at: '2026-10-04T18:30:00Z' });
    const closed = { ...issue(1, []), body: done, open: false };
    expect(recentWrites([closed], now)).toBe(2); // x/3 is over an hour old; x/4 wasn't a write
    const { items, budget } = planStep([closed, issue(2, ['a/1', 'a/2', 'a/3', 'a/4', 'a/5'])], known, now);
    expect(budget).toBe(3);
    expect(items.map((i) => i.target)).toEqual(['a/1', 'a/2', 'a/3']);
  });

  it('plans nothing once 5 writes landed this hour, however often it runs', () => {
    const now = new Date('2026-10-04T19:00:00Z');
    let b = body(['a/1', 'a/2', 'a/3', 'a/4', 'a/5', 'a/6']);
    for (let i = 1; i <= 5; i++) b = recordResult(b, { issue: 1, change: 'x', target: `a/${i}`, outcome: i === 5 ? 'failed' : 'applied', before: 'a', after: 'b', at: '2026-10-04T18:45:00Z' });
    const { items, budget } = planStep([{ ...issue(1, []), body: b }], known, now);
    expect(budget).toBe(0);
    expect(items).toEqual([]);
  });

  it('skips unknown change types', () => {
    const { items, skipped } = planStep([issue(1, ['a/1'])], ['something-else']);
    expect(items).toEqual([]);
    expect(skipped[0].reason).toContain('unknown change');
  });
});

describe('default-branch ruleset', () => {
  it('accepts the ruleset git-steer creates', () => {
    expect(evaluateRuleset({ id: 1, ...desiredRuleset() }).state).toBe('compliant');
  });

  it('flags a missing or weakened ruleset', () => {
    expect(evaluateRuleset(null)).toEqual({ state: 'noncompliant', detail: 'no git-steer ruleset' });
    const weak = { ...desiredRuleset(), enforcement: 'evaluate', rules: [{ type: 'deletion' }], bypass_actors: [] };
    const r = evaluateRuleset(weak);
    expect(r.state).toBe('noncompliant');
    expect(r.detail).toContain('enforcement evaluate');
    expect(r.detail).toContain('missing rules: non_fast_forward, pull_request, required_linear_history, required_signatures');
    expect(r.detail).toContain('no admin bypass');
  });
});

describe('applyToTarget', () => {
  const fake = (states: CheckResult[], onApply: () => void = () => {}): Change => ({
    id: 'fake', target: 'repo', summary: '',
    check: async () => states.shift()!,
    apply: async () => onApply(),
  });
  const ok = { state: 'compliant', detail: 'ok' } as const;
  const no = { state: 'noncompliant', detail: 'missing' } as const;
  const octokit = {} as Octokit;

  it('never writes to a compliant, unavailable or unknown target (C-010-006)', async () => {
    let writes = 0;
    for (const s of [ok, { state: 'unavailable', detail: 'plan' } as const, { state: 'unknown', detail: '500' } as const]) {
      await applyToTarget(fake([s], () => writes++), octokit, 1, 'a/b');
    }
    expect(writes).toBe(0);
  });

  it('applies, then verifies (C-010-004)', async () => {
    expect((await applyToTarget(fake([no, ok]), octokit, 1, 'a/b')).outcome).toBe('applied');
    const failed = await applyToTarget(fake([no, no]), octokit, 1, 'a/b');
    expect(failed.outcome).toBe('failed');
    expect(failed.after).toContain('still noncompliant');
  });

  it('records an apply error as failed', async () => {
    const r = await applyToTarget(fake([no], () => { throw Object.assign(new Error('Validation Failed'), { status: 422 }); }), octokit, 1, 'a/b');
    expect(r).toMatchObject({ outcome: 'failed', after: 'apply error 422 Validation Failed' });
  });
});

describe('security settings', () => {
  const all = { dependabotAlerts: 'on', securityUpdates: 'on', secretScanning: 'on', pushProtection: 'on' } as const;

  it('reads security_and_analysis, treating absent on a private repo as a plan limit', () => {
    expect(analysisState('enabled', false)).toBe('on');
    expect(analysisState('disabled', true)).toBe('off');
    expect(analysisState(undefined, true)).toBe('unavailable');
    expect(analysisState(undefined, false)).toBe('unknown');
  });

  it('is compliant when everything the plan allows is on', () => {
    expect(evaluateSettings(all)).toEqual({ state: 'compliant', detail: 'on' });
    expect(evaluateSettings({ ...all, secretScanning: 'unavailable', pushProtection: 'unavailable' }))
      .toEqual({ state: 'compliant', detail: 'on; not on this plan: secret scanning, push protection' });
  });

  it('names what is off, and never calls an unreadable repo compliant', () => {
    expect(evaluateSettings({ ...all, secretScanning: 'off', pushProtection: 'off' }))
      .toEqual({ state: 'noncompliant', detail: 'off: secret scanning, push protection' });
    expect(evaluateSettings({ ...all, securityUpdates: 'unknown' }).state).toBe('unknown');
  });

  it('turns on only what is off, alerts before fix PRs, scanning and push protection together', async () => {
    const calls: string[] = [];
    const answers: Record<string, unknown> = {
      'GET /repos/{owner}/{repo}': { private: false, security_and_analysis: { secret_scanning: { status: 'disabled' }, secret_scanning_push_protection: { status: 'disabled' } } },
      'GET /repos/{owner}/{repo}/automated-security-fixes': { enabled: false, paused: false },
    };
    const octokit = {
      request: async (route: string, params: Record<string, unknown>) => {
        calls.push(route.startsWith('PATCH') ? `${route} ${JSON.stringify(params.security_and_analysis)}` : route);
        if (route === 'GET /repos/{owner}/{repo}/vulnerability-alerts') throw Object.assign(new Error('Not Found'), { status: 404 });
        return { data: answers[route] ?? {} };
      },
    } as unknown as Octokit;
    expect((await securitySettings.check(octokit, 'a/b')).detail).toBe('off: Dependabot alerts, Dependabot fix PRs, secret scanning, push protection');
    calls.length = 0;
    await securitySettings.apply(octokit, 'a/b');
    expect(calls.filter((c) => !c.startsWith('GET'))).toEqual([
      'PUT /repos/{owner}/{repo}/vulnerability-alerts',
      'PUT /repos/{owner}/{repo}/automated-security-fixes',
      'PATCH /repos/{owner}/{repo} {"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}',
    ]);
  });
});

describe('sponsorships', () => {
  const base = { isFork: false, isArchived: false, hasSponsorshipsEnabled: false };

  it('is noncompliant when off, and leaves forks and archived repos alone', () => {
    expect(evaluateSponsorships(base)).toEqual({ state: 'noncompliant', detail: 'Sponsorships off' });
    expect(evaluateSponsorships({ ...base, hasSponsorshipsEnabled: true }).state).toBe('compliant');
    expect(evaluateSponsorships({ ...base, isFork: true }).state).toBe('unavailable');
    expect(evaluateSponsorships({ ...base, isArchived: true }).state).toBe('unavailable');
  });

  it('turns it on through updateRepository with the repo node id', async () => {
    const calls: { query: string; vars: Record<string, unknown> }[] = [];
    const octokit = {
      graphql: async (query: string, vars: Record<string, unknown>) => {
        calls.push({ query, vars });
        return { repository: { id: 'R_1', ...base } };
      },
    } as unknown as Octokit;
    expect((await sponsorships.check(octokit, 'a/b')).state).toBe('noncompliant');
    await sponsorships.apply(octokit, 'a/b');
    const write = calls.find((c) => c.query.startsWith('mutation'));
    expect(write?.query).toContain('hasSponsorshipsEnabled:true');
    expect(write?.vars).toEqual({ id: 'R_1' });
  });

  it('reports an unreadable repo as unknown, never compliant', async () => {
    const octokit = { graphql: async () => { throw Object.assign(new Error('Not Found'), { status: 404 }); } } as unknown as Octokit;
    expect((await sponsorships.check(octokit, 'a/b')).state).toBe('unknown');
  });
});
