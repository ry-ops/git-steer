/**
 * Fleet status schema (ADR-009).
 *
 * status.json is the source the dashboard is rendered from, and the contract
 * any later view is built on. Change it only by bumping SCHEMA.
 */

export const SCHEMA = 'git-steer/fleet-status@2';

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

/**
 * Repo settings that aren't security coverage, so they never count as a
 * coverage gap. skipped - deliberately left off (e.g. Sponsorships on a fork).
 */
export type SettingState = 'on' | 'off' | 'skipped' | 'unknown';

export interface Settings {
  sponsorships: SettingState;
}

export type SettingKey = keyof Settings;

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
  settings: Settings;
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

/** One open Dependabot alert, as listed in a single-repo scan. */
export interface CveAlert {
  number: number;
  ghsa: string;
  cve: string | null;
  package: string;
  ecosystem: string;
  manifest: string;
  severity: string;
  fixedIn: string | null;
  url: string;
  /** "direct" or "transitive", when GitHub says. */
  relationship?: string;
  /** "runtime" or "development", when GitHub says. */
  scope?: string;
}

/**
 * A single-repo scan: the same status a fleet report records for the repo,
 * plus its open Dependabot alerts one by one. alerts is null when Dependabot
 * alerts aren't on or couldn't be read (C-009-001).
 */
export interface RepoScan {
  generatedAt: string;
  app: string;
  runUrl?: string;
  archived: boolean;
  status: RepoStatus;
  alerts: CveAlert[] | null;
}
