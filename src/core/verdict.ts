/**
 * Functional-integrity verdict logic (ADR-005).
 *
 * The aggregation rules here are the doctrinal crux — they encode C-005-002
 * and C-005-003, the three-state verdict that defeats the false-GO trap
 * (green-by-absence is NOT a pass). The reusable verify-functional-form
 * workflow mirrors this logic; this module is the canonical, tested source.
 */

export type DimResult = 'PASS' | 'FAIL' | 'NOT_APPLICABLE';
export type Dimension = 'BUILD' | 'TEST' | 'SMOKE' | 'SURFACE';
export type Verdict = 'GO' | 'NO-GO' | 'GO-UNVERIFIED';

export interface DimensionResult {
  dimension: Dimension;
  result: DimResult;
  detail?: string;
}

/**
 * Aggregate per-dimension results into a single verdict (ADR-005 C-005-002/003):
 *   - any dimension FAILED            -> NO-GO
 *   - else at least one PASSED        -> GO        (real verification happened)
 *   - else (nothing failed, nothing
 *     actually executed)              -> GO-UNVERIFIED  (green-by-absence)
 */
export function aggregateVerdict(dims: DimensionResult[]): Verdict {
  if (dims.some((d) => d.result === 'FAIL')) return 'NO-GO';
  if (dims.some((d) => d.result === 'PASS')) return 'GO';
  return 'GO-UNVERIFIED';
}

/** May this verdict auto-merge? Only a GO (C-005-003: GO-UNVERIFIED is held). */
export function mayAutoMerge(verdict: Verdict): boolean {
  return verdict === 'GO';
}

/** Provenance record persisted to git-steer-state (ADR-005 C-005-006). */
export interface VerdictRecord {
  repo: string;
  pr: number | null;
  branch: string;
  sourceSha: string;
  verdict: Verdict;
  dimensions: DimensionResult[];
  timestamp: string;
}

export function makeVerdictRecord(
  repo: string,
  pr: number | null,
  branch: string,
  sourceSha: string,
  dimensions: DimensionResult[],
  timestamp: string,
): VerdictRecord {
  return { repo, pr, branch, sourceSha, verdict: aggregateVerdict(dimensions), dimensions, timestamp };
}

/**
 * SURFACE heuristic for a dependency bump (ADR-005 C-005-002): a breaking
 * version jump is FAIL (held for human), a same-major bump is PASS, and an
 * unknown/absent bump is NOT_APPLICABLE. Honors 0.x semver, where a minor
 * bump is breaking (0.25.x -> 0.28.1 is a breaking jump).
 */
export function surfaceForBump(fromVersion?: string, toVersion?: string): DimensionResult {
  const parse = (v?: string): number[] | null => {
    if (!v) return null;
    const m = v.replace(/^[^0-9]*/, '').match(/^(\d+)\.(\d+)\.(\d+)/);
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  };
  const a = parse(fromVersion);
  const b = parse(toVersion);
  if (!a || !b) return { dimension: 'SURFACE', result: 'NOT_APPLICABLE', detail: 'no parseable bump info' };

  const breaking = a[0] !== b[0] || (a[0] === 0 && a[1] !== b[1]); // 0.x: minor is breaking
  return breaking
    ? { dimension: 'SURFACE', result: 'FAIL', detail: `breaking version jump ${fromVersion} -> ${toVersion}` }
    : { dimension: 'SURFACE', result: 'PASS', detail: `same-major bump ${fromVersion} -> ${toVersion}` };
}
