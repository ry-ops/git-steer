import { describe, it, expect } from 'vitest';
import { buildHandoffs, ciNeed, markerKey, MAX_CI_REPOS, MAX_HANDOFFS, parseHandoffRequest, planCiHandoffs, planRepoHandoffs, renderHandoffReply, targetVersion } from '../fleet/handoff.js';
import type { CiHealth, FixPlan, PlannedPr } from '../fleet/fix.js';
import type { CveAlert } from '../fleet/types.js';

const alert = (over: Partial<CveAlert>): CveAlert => ({
  number: 1, ghsa: 'GHSA-aaaa-bbbb-cccc', cve: 'CVE-2026-1', package: 'tar', ecosystem: 'npm', manifest: 'package-lock.json',
  severity: 'critical', fixedIn: '7.5.19', url: 'https://github.com/x/y/security/dependabot/1', relationship: 'transitive', scope: 'runtime', ...over,
});

function plan(isPrivate: boolean, uncovered: CveAlert[], noFix: CveAlert[], prs: PlannedPr[] = [], ci?: CiHealth, repo = 'git-fabric/gateway'): FixPlan {
  return {
    repo, prs, uncovered, noFix, ci,
    scan: {
      generatedAt: '2026-10-10T17:00:00Z', app: 'git-steer-reporter', archived: false, alerts: [...uncovered, ...noFix],
      status: {
        repo, owner: repo.split('/')[0], private: isPrivate, defaultBranch: 'main', url: `https://github.com/${repo}`,
        coverage: { dependabotAlerts: 'on', dependabotSecurityUpdates: 'on', codeScanning: 'on', secretScanning: 'on', pushProtection: 'on', branchProtection: 'on' },
        settings: { sponsorships: 'on' },
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
    const file = planRepoHandoffs(plan(false, tar, request));
    const [up, rep] = file.targets[0].handoffs;
    const md = renderHandoffReply(file, [
      { repo: 'git-fabric/gateway', key: up.key, title: up.title, url: 'https://x/1', state: 'opened' },
      { repo: 'git-fabric/gateway', key: rep.key, title: rep.title, url: 'https://x/2', state: 'already-open' },
    ]);
    expect(md).toContain(`| [${up.title}](https://x/1) | 🆕 opened |`);
    expect(md).toContain('↩️ already open');
    expect(md).toContain('Assign to Copilot');
    expect(md).toContain('git-steer never assigns these itself');
    expect(md).toContain('is public');
  });

  it('shows a planned issue with no result as not opened', () => {
    const file = planRepoHandoffs(plan(false, tar, []));
    expect(renderHandoffReply(file, [])).toContain('❌ failed: not opened (see the run)');
  });

  it('says so when there is nothing to hand off', () => {
    expect(renderHandoffReply(planRepoHandoffs(plan(false, [], [])), [])).toContain('Nothing to hand off');
  });
});

const pr = (n: number, state: PlannedPr['state'], detail = ''): PlannedPr =>
  ({ number: n, title: `bump ${n}`, url: `https://x/pull/${n}`, state, detail, updates: [], closes: [], bump: 'minor' });
const main = (state: 'ready' | 'untested' | 'failing' | 'running', detail: string): CiHealth =>
  ({ main: { state, detail, sha: 'abcdef1234567' }, workflows: ['codeql.yml'] });

describe('CI hand-offs', () => {
  it('parses the request shapes', () => {
    expect(parseHandoffRequest('handoff git-fabric/gateway')).toEqual({ repo: 'git-fabric/gateway' });
    expect(parseHandoffRequest('handoff ci fleet')).toEqual({ ci: true, owner: undefined });
    expect(parseHandoffRequest('Handoff CI all')).toEqual({ ci: true, owner: undefined });
    expect(parseHandoffRequest('handoff ci cortex-io')).toEqual({ ci: true, owner: 'cortex-io' });
    expect(parseHandoffRequest('handoff ')).toBeNull();
  });

  it('asks for CI when nothing builds or tests the repo, naming the scanners', () => {
    const p = plan(false, [], [], [pr(1, 'untested'), pr(2, 'untested')], main('untested', 'only scanners passed (CodeQL, Codacy); nothing built or tested it'));
    expect(ciNeed(p)).toEqual({ kind: 'missing', scanners: ['CodeQL', 'Codacy'] });
    const [h] = buildHandoffs(p);
    expect(h.key).toBe('git-fabric/gateway:ci:add');
    expect(h.title).toBe('Add CI that builds and tests this repo');
    expect(h.body).toContain('2 Dependabot pull requests are open');
    expect(h.body).toContain('scanners or linters (CodeQL, Codacy)');
    expect(h.body).toContain('`codeql.yml`');
    expect(h.body).toContain('`build-and-test`');
    expect(h.body).toContain("Dependabot pull requests don't receive them");
  });

  it('asks to fix CI that fails on the default branch', () => {
    const p = plan(false, [], [], [pr(1, 'ready')], main('failing', 'failed: test, build'));
    const [h] = buildHandoffs(p);
    expect(h.key).toBe('git-fabric/gateway:ci:fix');
    expect(h.title).toBe('Fix the failing CI on `main`');
    expect(h.body).toContain('(abcdef1) fails: `test`, `build`');
    expect(h.body).toContain('continue-on-error');
  });

  it('asks to fix CI when every Dependabot PR fails and none pass, tallying the checks', () => {
    const p = plan(false, [], [], [
      pr(1, 'failing', 'failed: test, deploy'), pr(2, 'failing', 'failed: test'), pr(3, 'skip'), pr(4, 'untested'),
    ], main('untested', 'no checks ran'));
    expect(ciNeed(p)).toEqual({ kind: 'broken', where: 'prs', failing: 2, of: 3, checks: [['test', 2], ['deploy', 1]] });
    const [h] = buildHandoffs(p);
    expect(h.title).toBe('Fix the CI that fails on every Dependabot pull request');
    expect(h.body).toContain('| `test` | 2 |');
  });

  it('leaves CI alone when any test passes, or when it can\'t tell', () => {
    expect(ciNeed(plan(false, [], [], [pr(1, 'ready'), pr(2, 'failing', 'failed: test')], main('untested', 'no checks ran')))).toBeNull();
    expect(ciNeed(plan(false, [], [], [pr(1, 'untested')], main('ready', 'passed: test')))).toBeNull();
    expect(ciNeed(plan(false, [], [], [pr(1, 'untested')], main('running', 'running: test')))).toBeNull();
    expect(ciNeed(plan(false, [], [], [pr(1, 'untested')], { main: null, workflows: null }))).toBeNull();
    expect(ciNeed(plan(false, [], [], [pr(1, 'untested')]))).toBeNull();
  });

  it('puts the CI issue before the dependency issues', () => {
    const p = plan(false, tar, request, [pr(1, 'untested')], main('untested', 'no checks ran'));
    expect(buildHandoffs(p).map((h) => h.key)).toEqual(['git-fabric/gateway:ci:add', 'git-fabric/gateway:upgrade', 'git-fabric/gateway:replace:request']);
  });

  it('plans one CI issue per repo that needs one, most open PRs first, capped', () => {
    const none = plan(false, [], [], [pr(1, 'untested')], main('untested', 'no checks ran'), 'a/one');
    const three = plan(false, [], [], [pr(1, 'failing', 'failed: t'), pr(2, 'failing', 'failed: t'), pr(3, 'failing', 'failed: t')], main('untested', 'no checks ran'), 'b/three');
    const fine = plan(false, [], [], [pr(1, 'ready')], main('ready', 'passed: t'), 'c/fine');
    const file = planCiHandoffs('fleet', [none, three, fine]);
    expect(file.targets.map((t) => [t.owner, t.name, t.handoffs.map((h) => h.key)])).toEqual([
      ['b', 'three', ['b/three:ci:fix']], ['a', 'one', ['a/one:ci:add']],
    ]);
    expect(file.healthy).toBe(1);
    const many = Array.from({ length: MAX_CI_REPOS + 2 }, (_, i) => plan(false, [], [], [pr(1, 'untested')], main('untested', 'no checks ran'), `o/r${i}`));
    const capped = planCiHandoffs('o', many);
    expect(capped.targets).toHaveLength(MAX_CI_REPOS);
    expect(capped.dropped).toBe(2);
  });

  it('replies for a fleet CI request with a row per repo', () => {
    const p = plan(false, [], [], [pr(1, 'untested')], main('untested', 'no checks ran'), 'a/one');
    const file = planCiHandoffs('fleet', [p], [{ repo: 'x/y', message: 'boom' }]);
    const md = renderHandoffReply(file, [{ repo: 'a/one', key: 'a/one:ci:add', title: 'Add CI that builds and tests this repo', url: 'https://x/9', state: 'opened' }]);
    expect(md).toContain('## git-steer hand-off: CI for fleet');
    expect(md).toContain('| [a/one](https://github.com/a/one) | [Add CI that builds and tests this repo](https://x/9) | 🆕 opened |');
    expect(md).toContain('- x/y: boom');
  });
});
