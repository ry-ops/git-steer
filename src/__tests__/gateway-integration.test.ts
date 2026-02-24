import { describe, it, expect } from 'vitest';
import { initGateway } from '../fabric/gateway.js';

/**
 * Integration tests for the Fabric gateway.
 *
 * These hit real GitHub infrastructure via @git-fabric/cve,
 * so they require a valid GITHUB_TOKEN and are skipped in CI
 * when the token is absent.
 */

const token = process.env.GITHUB_TOKEN ?? process.env.GIT_STEER_TOKEN;
const stateRepo = process.env.STATE_REPO ?? 'ry-ops/git-steer-state';
const managedRepos = (process.env.MANAGED_REPOS ?? 'ry-ops/git-steer,ry-ops/blog').split(',');

describe.skipIf(!token)('gateway integration', () => {
  // ── 2a: Live gateway initialization ─────────────────────────────────────

  it('initializes with real token and state repo', async () => {
    const handle = await initGateway({
      githubToken: token!,
      stateRepo,
      managedRepos,
    });

    expect(handle.available).toBe(true);
    expect(handle.appCount).toBeGreaterThanOrEqual(1);
    // The CVE app registers 8 tools
    expect(handle.toolCount).toBeGreaterThanOrEqual(8);
    expect(handle.router).toBeDefined();
  }, 30_000); // generous timeout for network calls

  // ── 2b: Route cve_queue_stats (read-only, safe) ─────────────────────────

  it('routes cve_queue_stats and returns expected shape', async () => {
    const handle = await initGateway({
      githubToken: token!,
      stateRepo,
      managedRepos,
    });

    const result = await handle.router.route('cve_queue_stats', {});

    expect(result).toBeDefined();
    expect(result.durationMs).toBeGreaterThan(0);

    // The result payload lives in result.result (string or object)
    const payload =
      typeof result.result === 'string'
        ? JSON.parse(result.result)
        : result.result;

    expect(payload).toHaveProperty('total');
    expect(payload).toHaveProperty('byStatus');
    expect(payload).toHaveProperty('pendingBySeverity');
  }, 30_000);

  // ── 2c: Route cve_queue_list with filters ───────────────────────────────

  it('routes cve_queue_list with filters and returns expected shape', async () => {
    const handle = await initGateway({
      githubToken: token!,
      stateRepo,
      managedRepos,
    });

    const result = await handle.router.route('cve_queue_list', {
      status: 'all',
      limit: 5,
    });

    expect(result).toBeDefined();

    const payload =
      typeof result.result === 'string'
        ? JSON.parse(result.result)
        : result.result;

    expect(payload).toHaveProperty('total');
    expect(payload).toHaveProperty('entries');
  }, 30_000);
});
