/**
 * Fleet status schema (ADR-009).
 *
 * status.json is the source the dashboard is rendered from, and the contract
 * any later view is built on. Change it only by bumping SCHEMA.
 */

export const SCHEMA = 'git-steer/fleet-status@1';

/**
 * on          - the detector or setting is enabled
 * off         - GitHub reports it disabled; it can be turned on
 * unavailable - GitHub says the repo's plan doesn't include it
 * unknown     - git-steer couldn't tell (not visible, or an unexpected error)
 */
export type CoverageState = 'on' | 'off' | 'unavailable' | 'unknown';

export interface Coverage {
  dependabotAlerts: CoverageState;
  dependabotSecurityUpdates: CoverageState;
  codeScanning: CoverageState;
  secretScanning: CoverageState;
  pushProtection: CoverageState;
  branchProtection: CoverageState;
}

export type CoverageKey = keyof Coverage;

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface NoPatchAlert {
  number: number;
  ghsa: string;
  package: string;
  severity: string;
  url: string;
}

export interface StalePr {
  number: number;
  title: string;
  ageDays: number;
  url: string;
}

export interface UndocumentedDismissal {
  number: number;
  ghsa: string;
  package: string;
  url: string;
}

/** Findings for one repo. A tool's field is null when its coverage isn't 'on' (C-009-001). */
export interface Findings {
  dependabot: SeverityCounts | null;
  codeScanning: SeverityCounts | null;
  secretScanning: number | null;
  noPatch: NoPatchAlert[];
  staleDependabotPrs: StalePr[];
  undocumentedDismissals: UndocumentedDismissal[];
}

export interface RepoStatus {
  repo: string;
  owner: string;
  private: boolean;
  defaultBranch: string;
  url: string;
  coverage: Coverage;
  findings: Findings;
  config: 'present' | 'absent' | 'unknown';
  errors: string[];
}

export interface FleetStatus {
  schema: typeof SCHEMA;
  generatedAt: string;
  app: string;
  runUrl?: string;
  owners: { account: string; repos: number }[];
  repos: RepoStatus[];
}
