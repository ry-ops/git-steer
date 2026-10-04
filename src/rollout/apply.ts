/**
 * One target, one job (ADR-010): check, apply only if needed, check again.
 */

import type { Octokit } from 'octokit';
import type { Change, TargetResult } from './types.js';

export async function applyToTarget(
  change: Change, octokit: Octokit, issue: number, target: string, runUrl?: string,
): Promise<TargetResult> {
  const at = () => new Date().toISOString();
  const before = await change.check(octokit, target);
  const base = { issue, change: change.id, target, runUrl };

  if (before.state === 'compliant') return { ...base, outcome: 'already-compliant', before: before.detail, after: before.detail, at: at() };
  if (before.state === 'unavailable') return { ...base, outcome: 'unavailable', before: before.detail, after: before.detail, at: at() };
  if (before.state === 'unknown') return { ...base, outcome: 'failed', before: before.detail, after: 'not written: state unknown', at: at() };

  try {
    await change.apply(octokit, target);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    return { ...base, outcome: 'failed', before: before.detail, after: `apply error ${e.status ?? ''} ${e.message ?? ''}`.trim(), at: at() };
  }

  // C-010-004: verify after write.
  const after = await change.check(octokit, target);
  return {
    ...base,
    outcome: after.state === 'compliant' ? 'applied' : 'failed',
    before: before.detail,
    after: after.state === 'compliant' ? after.detail : `still ${after.state}: ${after.detail}`,
    at: at(),
  };
}
