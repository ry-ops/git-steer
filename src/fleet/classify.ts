/**
 * Turns GitHub's answers into coverage states.
 *
 * GitHub signals "disabled" and "your plan doesn't include this" through
 * status codes and messages, and the two must never be confused: "off" is a
 * setting to turn on, "unavailable" is a plan decision.
 */

import type { CoverageState, SeverityCounts } from './types.js';

/** GitHub's answers when a feature needs a paid plan, not a setting change. */
export function isPlanLimited(message: string): boolean {
  return /upgrade to github (pro|team)|advanced security must be enabled/i.test(message);
}

export function dependabotAlertsState(status: number, message: string): CoverageState {
  if (status === 200) return 'on';
  if (status === 403 && /disabled/i.test(message)) return 'off';
  return 'unknown';
}

/**
 * @param defaultSetup  the code-scanning default-setup state, when known. A
 *   repo with default setup "configured" but no analysis yet (first scan
 *   pending, or no language CodeQL supports) counts as on: there's nothing to
 *   turn on.
 */
export function codeScanningState(status: number, message: string, defaultSetup?: string): CoverageState {
  if (status === 200) return 'on';
  if (status === 403 && (isPlanLimited(message) || /code security/i.test(message))) return 'unavailable';
  if (status === 404 && defaultSetup === 'configured') return 'on';
  if (status === 404) return 'off'; // no analysis found, and default setup isn't configured
  if (status === 403 && /disabled|not enabled/i.test(message)) return 'off';
  return 'unknown';
}

export function secretScanningState(status: number, message: string): CoverageState {
  if (status === 200) return 'on';
  if (status === 404) return 'off'; // "Secret scanning is disabled on this repository."
  if (status === 403 && isPlanLimited(message)) return 'unavailable';
  if (status === 403 && /disabled|not enabled/i.test(message)) return 'off';
  return 'unknown';
}

/**
 * Dependabot security updates (fix PRs), from GET .../automated-security-fixes,
 * which answers for private repos too. Paused counts as off: no PRs are opened.
 * Falls back to security_and_analysis when that endpoint can't be read.
 */
export function securityUpdatesState(
  answer: { status: number; data: { enabled?: boolean; paused?: boolean } | null },
  fallback: string | undefined,
): CoverageState {
  if (answer.status === 200 && answer.data) return answer.data.enabled && !answer.data.paused ? 'on' : 'off';
  return settingState(fallback);
}

/** security_and_analysis.<feature>.status → coverage. Absent means GitHub didn't show it. */
export function settingState(status: string | undefined): CoverageState {
  if (status === 'enabled') return 'on';
  if (status === 'disabled') return 'off';
  return 'unknown';
}

/**
 * Branch protection from the two sources GitHub has: rulesets that apply to
 * the default branch, and classic protection.
 */
export function branchProtectionState(
  rules: { status: number; message: string; count: number },
  classic: { status: number; message: string },
): CoverageState {
  if (classic.status === 200 || (rules.status === 200 && rules.count > 0)) return 'on';
  if ((classic.status === 403 && isPlanLimited(classic.message)) || (rules.status === 403 && isPlanLimited(rules.message))) {
    return 'unavailable';
  }
  if (classic.status === 404 && rules.status === 200 && rules.count === 0) return 'off';
  return 'unknown';
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

/** Adds one alert's severity to a count. GitHub's "moderate" and "warning"/"note" are folded in. */
export function addSeverity(counts: SeverityCounts, severity: string | null | undefined): void {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical':
      counts.critical++;
      break;
    case 'high':
    case 'error':
      counts.high++;
      break;
    case 'medium':
    case 'moderate':
    case 'warning':
      counts.medium++;
      break;
    default:
      counts.low++;
  }
}

export function ageInDays(createdAt: string, now: Date): number {
  return Math.floor((now.getTime() - new Date(createdAt).getTime()) / 86_400_000);
}
