import { describe, it, expect } from 'vitest';
import { MAX_BODY } from '../fleet/render.js';
import { parseScanTarget, renderScan } from '../fleet/scan.js';
import type { CveAlert, RepoScan } from '../fleet/types.js';

function scan(over: Partial<RepoScan> = {}): RepoScan {
  return {
    generatedAt: '2026-10-10T09:00:00.000Z', app: 'git-steer-reporter', archived: false, alerts: [],
    status: {
      repo: 'acme/a', owner: 'acme', private: true, defaultBranch: 'main', url: 'https://github.com/acme/a',
      coverage: {
        dependabotAlerts: 'on', dependabotSecurityUpdates: 'on', codeScanning: 'unavailable',
        secretScanning: 'on', pushProtection: 'on', branchProtection: 'on',
      },
      findings: {
        dependabot: { critical: 0, high: 0, medium: 0, low: 0 }, codeScanning: null,
        secretScanning: 0, noPatch: [], staleDependabotPrs: [], undocumentedDismissals: [],
      },
      config: 'absent', errors: [],
    },
    ...over,
  };
}

function alert(over: Partial<CveAlert> = {}): CveAlert {
  return {
    number: 1, ghsa: 'GHSA-aaaa', cve: 'CVE-2026-0001', package: 'left-pad', ecosystem: 'npm',
    manifest: 'package-lock.json', severity: 'low', fixedIn: '1.2.3', url: 'https://x/1', ...over,
  };
}

describe('parseScanTarget', () => {
  it('reads the repo from the forms a request can take', () => {
    expect(parseScanTarget('scan ry-ops/git-steer')).toBe('ry-ops/git-steer');
    expect(parseScanTarget('Scan: git-fabric/fabric-ctrl')).toBe('git-fabric/fabric-ctrl');
    expect(parseScanTarget('scan https://github.com/TAEM-DEV/adrs/pulls')).toBe('TAEM-DEV/adrs');
    expect(parseScanTarget('scan ry-ops/blog.old.git')).toBe('ry-ops/blog.old');
    // The "Scan a repo" issue form: title "scan ", repo in the body.
    expect(parseScanTarget('scan \n### Repo to scan\n\ngit-fabric/gateway')).toBe('git-fabric/gateway');
  });

  it('returns null when no repo is named', () => {
    expect(parseScanTarget('scan everything')).toBeNull();
    expect(parseScanTarget('scan acme/..')).toBeNull();
    expect(parseScanTarget('')).toBeNull();
  });
});

describe('renderScan', () => {
  it('lists alerts worst first, flagging ones with no fix', () => {
    const md = renderScan(scan({ alerts: [alert(), alert({ number: 2, ghsa: 'GHSA-bbbb', severity: 'critical', package: 'chromadb', fixedIn: null, cve: null })] }));
    expect(md).toContain('### Open Dependabot alerts (2)');
    expect(md.indexOf('GHSA-bbbb')).toBeLessThan(md.indexOf('GHSA-aaaa'));
    expect(md).toContain('| critical | chromadb (npm) | [GHSA-bbbb](https://x/1) | — | **no fix yet** |');
  });

  it('says unknown, never zero, when a tool is off (C-009-001)', () => {
    const s = scan({ alerts: null });
    s.status.coverage.dependabotAlerts = 'off';
    s.status.findings.dependabot = null;
    const md = renderScan(s);
    expect(md).toContain('**Dependabot alerts:** unknown (not on)');
    expect(md).toContain('CVEs are unknown, not zero');
    expect(md).toContain('- Turned off: Dependabot alerts.');
  });

  it('says so when the repo is clean', () => {
    const md = renderScan(scan());
    expect(md).toContain('No open Dependabot alerts. ✅');
    expect(md).toContain('Nothing needs a human decision. 🎉');
  });

  it('stays under the comment limit', () => {
    const alerts = Array.from({ length: 3000 }, (_, i) => alert({ number: i, ghsa: `GHSA-${i}`, manifest: 'x/'.repeat(30) + 'package-lock.json' }));
    const md = renderScan(scan({ alerts }));
    expect(md.length).toBeLessThanOrEqual(MAX_BODY);
    expect(md).toContain('more |');
  });
});
