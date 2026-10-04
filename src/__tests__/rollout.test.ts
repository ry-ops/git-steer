import { describe, it, expect } from 'vitest';
import type { Octokit } from 'octokit';
import { desiredRuleset, evaluateRuleset } from '../rollout/changes/default-branch-ruleset.js';
import { parseRolloutIssue, recordResult, remaining, renderRolloutIssue } from '../rollout/issue.js';
import { planStep } from '../rollout/plan.js';
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
    number: n, body: body(targets), labels: ['git-steer-rollout', 'approved'], openedByGitSteer: true, approvedByOwner: true, ...over,
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
