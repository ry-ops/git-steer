import { describe, it, expect } from 'vitest';
import { buildHandoffs, markerKey, MAX_HANDOFFS, renderHandoffReply, targetVersion } from '../fleet/handoff.js';
import type { FixPlan } from '../fleet/fix.js';
import type { CveAlert } from '../fleet/types.js';

const alert = (over: Partial<CveAlert>): CveAlert => ({
  number: 1, ghsa: 'GHSA-aaaa-bbbb-cccc', cve: 'CVE-2026-1', package: 'tar', ecosystem: 'npm', manifest: 'package-lock.json',
  severity: 'critical', fixedIn: '7.5.19', url: 'https://github.com/x/y/security/dependabot/1', relationship: 'transitive', scope: 'runtime', ...over,
});

function plan(isPrivate: boolean, uncovered: CveAlert[], noFix: CveAlert[]): FixPlan {
  return {
    repo: 'git-fabric/gateway', prs: [], uncovered, noFix,
    scan: {
      generatedAt: '2026-10-10T17:00:00Z', app: 'git-steer-reporter', archived: false, alerts: [...uncovered, ...noFix],
      status: {
        repo: 'git-fabric/gateway', owner: 'git-fabric', private: isPrivate, defaultBranch: 'main', url: 'https://github.com/git-fabric/gateway',
        coverage: { dependabotAlerts: 'on', dependabotSecurityUpdates: 'on', codeScanning: 'on', secretScanning: 'on', pushProtection: 'on', branchProtection: 'on' },
        findings: { dependabot: null, codeScanning: null, secretScanning: 0, noPatch: [], staleDependabotPrs: [], undocumentedDismissals: [] },
        config: 'absent', errors: [],
      },
    },
  };
}

const tar = [alert({ number: 1, fixedIn: '7.5.10' }), alert({ number: 2, fixedIn: '7.5.21' }), alert({ number: 3, fixedIn: '7.5.19' })];
const qs = [alert({ number: 4, package: 'qs', fixedIn: '6.14.1', scope: 'development' })];
const request = [alert({ number: 5, package: 'request', fixedIn: null, ghsa: 'GHSA-p8p7-x288-28g6', cve: 'CVE-2023-28155' })];

describe('hand-off issues', () => {
  it('targets the highest fixed version per package', () => {
    expect(targetVersion(tar)).toBe('7.5.21');
  });

  it('files one upgrade issue and one replace issue per package with no fix, with stable keys', () => {
    const h = buildHandoffs(plan(false, [...tar, ...qs], request));
    expect(h.map((x) => x.key)).toEqual(['git-fabric/gateway:upgrade', 'git-fabric/gateway:replace:request']);
    expect(h[0].title).toBe("Upgrade 2 dependencies Dependabot hasn't");
    expect(h[0].body).toContain('| `tar` | 7.5.21 | package-lock.json | transitive, runtime |');
    expect(h[0].body).toContain('`npm ls <package>`');
    expect(h[1].title).toBe('Remove or replace `request` (no fixed release)');
    expect(markerKey(h[1].body)).toBe('git-fabric/gateway:replace:request');
  });

  it('never puts advisory IDs, severities or alert links in a public repo (C-009-003)', () => {
    for (const h of buildHandoffs(plan(false, [...tar, ...qs], request))) {
      expect(h.body).not.toMatch(/GHSA-|CVE-|critical|security\/dependabot|Advisories/);
    }
  });

  it('includes the advisories for a private repo', () => {
    const [up, rep] = buildHandoffs(plan(true, tar, request));
    expect(up.body).toContain('Advisories (private repo)');
    expect(up.body).toContain('GHSA-aaaa-bbbb-cccc');
    expect(rep.body).toContain('CVE-2023-28155');
  });

  it('files at most MAX_HANDOFFS', () => {
    const many = Array.from({ length: 9 }, (_, i) => alert({ number: 10 + i, package: `pkg${i}`, fixedIn: null }));
    expect(buildHandoffs(plan(false, tar, many))).toHaveLength(MAX_HANDOFFS);
  });

  it('replies with links, says when an issue was already open, and never says it assigned anything', () => {
    const md = renderHandoffReply(plan(false, tar, request), [
      { key: 'a', title: 'Upgrade 1 dependency', url: 'https://x/1', state: 'opened' },
      { key: 'b', title: 'Remove request', url: 'https://x/2', state: 'already-open' },
    ], 0);
    expect(md).toContain('| [Upgrade 1 dependency](https://x/1) | 🆕 opened |');
    expect(md).toContain('↩️ already open');
    expect(md).toContain('Assign to Copilot');
    expect(md).toContain('git-steer never assigns these itself');
    expect(md).toContain('is public');
  });

  it('says so when there is nothing to hand off', () => {
    expect(renderHandoffReply(plan(false, [], []), [], 0)).toContain('Nothing to hand off');
  });
});
