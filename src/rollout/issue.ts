/**
 * The rollout issue (ADR-010): the record of one rollout. Its body holds the
 * change and one checkbox per target; git-steer ticks a box after each target
 * is done and checked. The first line is a marker git-steer reads back.
 */

import type { Outcome, TargetResult } from './types.js';

const MARKER = /^<!-- git-steer-rollout:v1 (\{.*\}) -->$/m;
const ITEM = /^- \[( |x)\] ([A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)?)(?: — (.*))?$/;

export interface RolloutItem {
  target: string;
  done: boolean;
  note: string;
  /** When git-steer wrote to this target (applied, or failed after trying), from the recorded note. */
  wroteAt: Date | null;
}

const WROTE = /^(✅ applied|❌ failed).*\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}) UTC\)/;

function wroteAt(note: string): Date | null {
  const m = note.match(WROTE);
  return m ? new Date(`${m[2].replace(' ', 'T')}:00Z`) : null;
}

export interface Rollout {
  change: string;
  items: RolloutItem[];
}

export function renderRolloutIssue(opts: {
  change: string;
  summary: string;
  targets: string[];
  startedBy: string;
  runUrl?: string;
  selector?: string;
}): { title: string; body: string } {
  const lines = [
    `<!-- git-steer-rollout:v1 ${JSON.stringify({ change: opts.change })} -->`,
    `## Rollout: \`${opts.change}\``,
    '',
    opts.summary,
    '',
    `Started by @${opts.startedBy}${opts.runUrl ? ` ([run](${opts.runUrl}))` : ''}${opts.selector ? ` from \`${opts.selector}\`` : ''}.`,
    '',
    '- **Approve:** add the `approved` label. Nothing is changed until the repo owner does.',
    '- **Pace:** at most 5 targets per hour, one per job, each checked after the write (ADR-010).',
    '- **Pause:** add the `paused` label. git-steer adds it itself if a check fails after a write.',
    '- **Cancel:** close this issue.',
    '',
    `### Targets (${opts.targets.length})`,
    '',
    ...opts.targets.map((t) => `- [ ] ${t}`),
    '',
  ];
  return { title: `Rollout: ${opts.change} (${opts.targets.length} targets)`, body: lines.join('\n') };
}

export function parseRolloutIssue(body: string): Rollout | null {
  const m = body.match(MARKER);
  if (!m) return null;
  let change: string;
  try {
    change = (JSON.parse(m[1]) as { change?: string }).change ?? '';
  } catch {
    return null;
  }
  if (!change) return null;
  const items: RolloutItem[] = [];
  for (const line of body.split('\n')) {
    const it = line.match(ITEM);
    if (it) items.push({ target: it[2], done: it[1] === 'x', note: it[3] ?? '', wroteAt: wroteAt(it[3] ?? '') });
  }
  return { change, items };
}

const OUTCOME_TEXT: Record<Outcome, string> = {
  'already-compliant': '✅ already compliant',
  applied: '✅ applied',
  unavailable: '— not available on this plan',
  failed: '❌ failed',
};

/** Ticks (or, on failure, annotates) one target's line. Failed targets stay unticked so they're retried after a person unpauses. */
export function recordResult(body: string, r: TargetResult): string {
  const run = r.runUrl ? ` · [run](${r.runUrl})` : '';
  const detail = r.outcome === 'applied' ? `${r.before} → ${r.after}` : r.outcome === 'failed' ? `${r.before} → ${r.after}` : r.after;
  const done = r.outcome !== 'failed';
  const replacement = `- [${done ? 'x' : ' '}] ${r.target} — ${OUTCOME_TEXT[r.outcome]}: ${detail.replace(/\n/g, ' ')} (${r.at.slice(0, 16).replace('T', ' ')} UTC)${run}`;
  return body
    .split('\n')
    .map((line) => {
      const it = line.match(ITEM);
      return it && it[2] === r.target ? replacement : line;
    })
    .join('\n');
}

export function remaining(rollout: Rollout): RolloutItem[] {
  return rollout.items.filter((i) => !i.done);
}
