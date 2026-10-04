import { describe, it, expect } from 'vitest';
import {
  addSeverity, ageInDays, branchProtectionState, codeScanningState, dependabotAlertsState,
  emptyCounts, isPlanLimited, secretScanningState, securityUpdatesState, settingState,
} from '../fleet/classify.js';
import { decisionCounts, MAX_BODY, renderDashboard } from '../fleet/render.js';
import { SCHEMA } from '../fleet/types.js';
import type { FleetStatus, RepoStatus } from '../fleet/types.js';

describe('classify', () => {
  it('tells plan limits apart from disabled settings', () => {
    expect(isPlanLimited('Upgrade to GitHub Pro or make this repository public to enable this feature.')).toBe(true);
    expect(isPlanLimited('Upgrade to GitHub Team to enable this feature.')).toBe(true);
    expect(isPlanLimited('Advanced Security must be enabled for this repository to use code scanning.')).toBe(true);
    expect(isPlanLimited('Secret scanning is disabled on this repository.')).toBe(false);
  });

  it('classifies the answers GitHub actually gives (probed 2026-10-04)', () => {
    expect(dependabotAlertsState(200, '')).toBe('on');
    expect(dependabotAlertsState(403, 'Dependabot alerts are disabled for this repository.')).toBe('off');
    expect(codeScanningState(403, 'Advanced Security must be enabled for this repository to use code scanning.')).toBe('unavailable');
    expect(codeScanningState(403, 'Code scanning is not enabled for this repository. Please enable code scanning in the repository settings.')).toBe('off');
    expect(codeScanningState(404, 'no analysis found')).toBe('off');
    expect(secretScanningState(404, 'Secret scanning is disabled on this repository.')).toBe('off');
    expect(dependabotAlertsState(500, 'boom')).toBe('unknown');
  });

  it('counts code scanning as on when default setup is configured but no analysis exists yet', () => {
    expect(codeScanningState(404, 'no analysis found', 'configured')).toBe('on');
    expect(codeScanningState(404, 'no analysis found', 'not-configured')).toBe('off');
    expect(codeScanningState(404, 'no analysis found')).toBe('off');
  });

  it('reads fix PRs from automated-security-fixes, falling back to security_and_analysis', () => {
    expect(securityUpdatesState({ status: 200, data: { enabled: true, paused: false } }, undefined)).toBe('on');
    expect(securityUpdatesState({ status: 200, data: { enabled: true, paused: true } }, 'enabled')).toBe('off');
    expect(securityUpdatesState({ status: 200, data: { enabled: false, paused: false } }, undefined)).toBe('off');
    expect(securityUpdatesState({ status: 403, data: null }, 'enabled')).toBe('on');
    expect(securityUpdatesState({ status: 403, data: null }, undefined)).toBe('unknown');
  });

  it('maps security_and_analysis statuses, treating absent as unknown', () => {
    expect(settingState('enabled')).toBe('on');
    expect(settingState('disabled')).toBe('off');
    expect(settingState(undefined)).toBe('unknown');
  });

  it('combines rulesets and classic protection', () => {
    const none = { status: 200, message: '', count: 0 };
    const absent = { status: 404, message: 'Branch not protected' };
    const plan = { status: 403, message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' };
    expect(branchProtectionState({ ...none, count: 2 }, absent)).toBe('on');
    expect(branchProtectionState(none, { status: 200, message: '' })).toBe('on');
    expect(branchProtectionState(none, absent)).toBe('off');
    expect(branchProtectionState({ status: 403, message: plan.message, count: 0 }, plan)).toBe('unavailable');
    expect(branchProtectionState({ status: 500, message: '', count: 0 }, absent)).toBe('unknown');
  });

  it('counts severities, folding GitHub synonyms', () => {
    const c = emptyCounts();
    for (const s of ['critical', 'high', 'moderate', 'medium', 'low', 'error', 'warning', 'note', undefined]) addSeverity(c, s);
    expect(c).toEqual({ critical: 1, high: 2, medium: 3, low: 3 });
  });

  it('computes age in whole days', () => {
    expect(ageInDays('2026-09-01T00:00:00Z', new Date('2026-09-16T12:00:00Z'))).toBe(15);
  });
});

function repo(name: string, over: Partial<RepoStatus> = {}): RepoStatus {
  return {
    repo: name, owner: name.split('/')[0], private: false, defaultBranch: 'main', url: `https://github.com/${name}`,
    coverage: {
      dependabotAlerts: 'on', dependabotSecurityUpdates: 'on', codeScanning: 'on',
      secretScanning: 'on', pushProtection: 'on', branchProtection: 'on',
    },
    findings: {
      dependabot: { critical: 0, high: 0, medium: 0, low: 0 }, codeScanning: { critical: 0, high: 0, medium: 0, low: 0 },
      secretScanning: 0, noPatch: [], staleDependabotPrs: [], undocumentedDismissals: [],
    },
    config: 'absent', errors: [], ...over,
  };
}

function fleet(repos: RepoStatus[]): FleetStatus {
  const owners = [...new Set(repos.map((r) => r.owner))].map((account) => ({ account, repos: repos.filter((r) => r.owner === account).length }));
  return { schema: SCHEMA, generatedAt: '2026-10-04T17:00:00.000Z', app: 'git-steer-reporter', owners, repos };
}

describe('renderDashboard', () => {
  it('says so when nothing needs a human', () => {
    const md = renderDashboard(fleet([repo('acme/a')]));
    expect(md).toContain('## Needs you (0)');
    expect(md).toContain('Nothing needs a human decision right now.');
  });

  it('lists only human decisions, with links', () => {
    const r = repo('acme/a');
    r.findings.noPatch.push({ number: 7, ghsa: 'GHSA-xxxx', package: 'left-pad', severity: 'high', url: 'https://x/7' });
    r.findings.staleDependabotPrs.push({ number: 3, title: 'Bump a | b', ageDays: 20, url: 'https://x/pr/3' });
    r.findings.undocumentedDismissals.push({ number: 9, ghsa: 'GHSA-yyyy', package: 'lodash', url: 'https://x/9' });
    const md = renderDashboard(fleet([r, repo('acme/b', { coverage: { ...r.coverage, branchProtection: 'off', codeScanning: 'off' } })]));
    expect(md).toContain('[GHSA-xxxx](https://x/7)');
    expect(md).toContain('[#3](https://x/pr/3) Bump a / b | 20 days');
    expect(md).toContain('Dismissed alerts with no reason (1)');
    expect(md).toContain('| acme/b | Code scanning |');
    expect(md).toContain('### No branch protection (1 repos)');
    expect(decisionCounts(fleet([r])).noPatch).toBe(1);
  });

  it('never counts a repo with a tool off as clean (C-009-001)', () => {
    const off = repo('acme/dark', {
      coverage: { ...repo('x/x').coverage, dependabotAlerts: 'off' },
      findings: { ...repo('x/x').findings, dependabot: null },
    });
    const md = renderDashboard(fleet([off]));
    expect(md).toContain('| acme/dark | Dependabot alerts |');
    expect(md).toMatch(/\| acme \| 1 \| 0\/0\/0\/0 \| 0\/0\/0\/0 \| 0 \| 1 \|/);
  });

  it('does not list plan limits as decisions', () => {
    const r = repo('acme/p', { private: true, coverage: { ...repo('x/x').coverage, codeScanning: 'unavailable', branchProtection: 'unavailable' } });
    const md = renderDashboard(fleet([r]));
    expect(md).toContain('## Needs you (0)');
    expect(md).toContain('| Branch protection | 0 | 0 | 1 | 0 |');
  });

  it('stays under the issue body limit for a large fleet', () => {
    const many = Array.from({ length: 400 }, (_, i) => {
      const r = repo(`acme/repo-${i}`, { coverage: { ...repo('x/x').coverage, codeScanning: 'off', branchProtection: 'off' } });
      for (let j = 0; j < 20; j++) r.findings.noPatch.push({ number: j, ghsa: `GHSA-${i}-${j}`, package: 'pkg', severity: 'low', url: `https://x/${i}/${j}` });
      return r;
    });
    const md = renderDashboard(fleet(many));
    expect(md.length).toBeLessThanOrEqual(MAX_BODY);
    expect(md).toContain('more in status.json');
  });
});
