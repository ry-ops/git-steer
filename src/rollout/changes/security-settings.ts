/**
 * security-settings (ADR-010, ADR-008 Layer 0).
 *
 * The free repo security settings, on wherever the repo's plan allows them:
 * Dependabot alerts, Dependabot security updates (fix PRs), secret scanning
 * and push protection. A setting the plan doesn't include (secret scanning on
 * a private repo without Advanced Security) is never written (C-010-006).
 *
 * Org repos under an enforced code security configuration are normally
 * already compliant: the configuration turned the settings on, so the check
 * passes and nothing is written. Repos owned by a personal account have no
 * such configuration; this change is how git-steer owns their settings.
 *
 * CodeQL default setup is not part of this change yet: it fails on repos
 * with no language CodeQL supports, which would pause whole rollouts.
 */

import type { Octokit } from 'octokit';
import type { Change, CheckResult } from '../types.js';

export type SettingState = 'on' | 'off' | 'unavailable' | 'unknown';

export interface SecuritySettings {
  dependabotAlerts: SettingState;
  securityUpdates: SettingState;
  secretScanning: SettingState;
  pushProtection: SettingState;
}

export const SETTING_LABELS: Record<keyof SecuritySettings, string> = {
  dependabotAlerts: 'Dependabot alerts',
  securityUpdates: 'Dependabot fix PRs',
  secretScanning: 'secret scanning',
  pushProtection: 'push protection',
};

const KEYS = Object.keys(SETTING_LABELS) as (keyof SecuritySettings)[];

/** A security_and_analysis status. Absent means the plan doesn't offer it on a private repo. */
export function analysisState(status: string | undefined, isPrivate: boolean): SettingState {
  if (status === 'enabled') return 'on';
  if (status === 'disabled') return 'off';
  return isPrivate ? 'unavailable' : 'unknown';
}

export function evaluateSettings(s: SecuritySettings): CheckResult {
  const named = (state: SettingState) => KEYS.filter((k) => s[k] === state).map((k) => SETTING_LABELS[k]);
  const off = named('off');
  const unknown = named('unknown');
  const unavailable = named('unavailable');
  if (off.length) return { state: 'noncompliant', detail: `off: ${off.join(', ')}` };
  if (unknown.length) return { state: 'unknown', detail: `can't tell: ${unknown.join(', ')}` };
  return { state: 'compliant', detail: `on${unavailable.length ? `; not on this plan: ${unavailable.join(', ')}` : ''}` };
}

function split(target: string): { owner: string; repo: string } {
  const [owner, repo] = target.split('/');
  if (!owner || !repo) throw new Error(`not a repo: ${target}`);
  return { owner, repo };
}

function statusOf(err: unknown): number {
  return (err as { status?: number }).status ?? 0;
}

export async function readSettings(octokit: Octokit, target: string): Promise<SecuritySettings> {
  const { owner, repo } = split(target);
  const { data: info } = await octokit.request('GET /repos/{owner}/{repo}', { owner, repo });
  const sa = (info as { security_and_analysis?: Record<string, { status?: string } | undefined> | null }).security_and_analysis ?? {};

  let dependabotAlerts: SettingState;
  try {
    await octokit.request('GET /repos/{owner}/{repo}/vulnerability-alerts', { owner, repo });
    dependabotAlerts = 'on'; // 204
  } catch (err) {
    dependabotAlerts = statusOf(err) === 404 ? 'off' : 'unknown';
  }

  let securityUpdates: SettingState;
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/automated-security-fixes', { owner, repo });
    securityUpdates = data.enabled && !data.paused ? 'on' : 'off';
  } catch (err) {
    securityUpdates = statusOf(err) === 404 ? 'off' : 'unknown';
  }

  return {
    dependabotAlerts,
    securityUpdates,
    secretScanning: analysisState(sa.secret_scanning?.status, info.private),
    pushProtection: analysisState(sa.secret_scanning_push_protection?.status, info.private),
  };
}

export const securitySettings: Change = {
  id: 'security-settings',
  target: 'repo',
  summary: 'Security settings: Dependabot alerts, Dependabot fix PRs, secret scanning and push protection on, wherever the plan allows.',

  async check(octokit, target) {
    try {
      return evaluateSettings(await readSettings(octokit, target));
    } catch (err) {
      const e = err as { status?: number; message?: string };
      return { state: 'unknown', detail: `${e.status ?? ''} ${e.message ?? ''}`.trim() };
    }
  },

  async apply(octokit, target) {
    const { owner, repo } = split(target);
    const s = await readSettings(octokit, target);
    // Fix PRs need alerts, so alerts first.
    if (s.dependabotAlerts === 'off') await octokit.request('PUT /repos/{owner}/{repo}/vulnerability-alerts', { owner, repo });
    if (s.securityUpdates === 'off') await octokit.request('PUT /repos/{owner}/{repo}/automated-security-fixes', { owner, repo });
    const analysis: Record<string, { status: 'enabled' }> = {};
    if (s.secretScanning === 'off') analysis.secret_scanning = { status: 'enabled' };
    // Push protection needs secret scanning on; send both in one request.
    if (s.pushProtection === 'off') analysis.secret_scanning_push_protection = { status: 'enabled' };
    if (Object.keys(analysis).length) {
      await octokit.request('PATCH /repos/{owner}/{repo}', { owner, repo, security_and_analysis: analysis });
    }
  },
};
