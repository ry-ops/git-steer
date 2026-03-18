import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

describe('Gateway env cleanup', () => {
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();

    // Snapshot env vars we care about
    savedEnv.GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    savedEnv.STATE_REPO = process.env.STATE_REPO;
    savedEnv.MANAGED_REPOS = process.env.MANAGED_REPOS;
  });

  afterEach(() => {
    // Restore env to pre-test state
    for (const key of ['GITHUB_TOKEN', 'STATE_REPO', 'MANAGED_REPOS'] as const) {
      if (savedEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = savedEnv[key];
      }
    }
  });

  function mockGatewayDeps() {
    const mockRegistry = {
      register: vi.fn(),
      list: vi.fn().mockReturnValue([{ name: 'cve' }]),
    };
    const mockRouter = {
      listTools: vi.fn().mockReturnValue([{ name: 'cve_scan' }]),
      route: vi.fn(),
    };

    vi.doMock('@git-fabric/gateway', () => ({
      createRegistry: vi.fn().mockReturnValue(mockRegistry),
      createRouter: vi.fn().mockReturnValue(mockRouter),
    }));

    vi.doMock('@git-fabric/cve', () => ({
      createApp: vi.fn().mockResolvedValue({ name: 'cve', tools: [] }),
    }));
  }

  it('cleans up GITHUB_TOKEN when it was not set before initGateway', async () => {
    delete process.env.GITHUB_TOKEN;
    delete process.env.STATE_REPO;
    delete process.env.MANAGED_REPOS;

    mockGatewayDeps();

    const { initGateway } = await import('../fabric/gateway.js');
    await initGateway({
      githubToken: 'ghp_temporary',
      stateRepo: 'ry-ops/git-steer-state',
      managedRepos: ['ry-ops/git-steer'],
    });

    expect(process.env.GITHUB_TOKEN).toBeUndefined();
    expect(process.env.STATE_REPO).toBeUndefined();
    expect(process.env.MANAGED_REPOS).toBeUndefined();
  });

  it('restores GITHUB_TOKEN to its original value when it was already set', async () => {
    process.env.GITHUB_TOKEN = 'ghp_original_value';
    process.env.STATE_REPO = 'original/state-repo';
    process.env.MANAGED_REPOS = 'original/repo1,original/repo2';

    mockGatewayDeps();

    const { initGateway } = await import('../fabric/gateway.js');
    await initGateway({
      githubToken: 'ghp_temporary',
      stateRepo: 'ry-ops/git-steer-state',
      managedRepos: ['ry-ops/git-steer'],
    });

    expect(process.env.GITHUB_TOKEN).toBe('ghp_original_value');
    expect(process.env.STATE_REPO).toBe('original/state-repo');
    expect(process.env.MANAGED_REPOS).toBe('original/repo1,original/repo2');
  });
});
