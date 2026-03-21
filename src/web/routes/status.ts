/**
 * Health and status routes
 *
 * GET /health            — health check
 * GET /api/status        — git-steer status
 * GET /api/taem/missions — list TAEM missions (future)
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { version: VERSION } = require('../../../package.json');

export async function registerStatusRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { github, state, gateway, token } = config;

  // Health check
  app.get('/health', async (_req, reply) => {
    return reply.send({
      status: 'ok',
      version: VERSION,
      timestamp: new Date().toISOString(),
    });
  });

  // Detailed status
  app.get('/api/status', async (_req, reply) => {
    let rateLimit = null;
    try {
      const rl = await github.getRateLimit();
      // Handle both GitHubClient (has .buckets) and TokenGitHubClient (returns raw rate object)
      if (rl && typeof rl === 'object') {
        if ('buckets' in rl) {
          rateLimit = {
            core: (rl as any).buckets?.['core'] ?? null,
            graphql: (rl as any).buckets?.['graphql'] ?? null,
          };
        } else if ('limit' in rl) {
          rateLimit = {
            core: { limit: (rl as any).limit, remaining: (rl as any).remaining, reset: (rl as any).reset },
            graphql: null,
          };
        }
      }
    } catch {
      // Non-fatal
    }

    // Safely access state methods (stub may not have all)
    const managedRepos = typeof state?.getManagedRepos === 'function' ? state.getManagedRepos() : [];
    const lastSync = typeof state?.getLastSync === 'function' ? state.getLastSync() : null;
    const isDirty = typeof state?.isDirty === 'function' ? state.isDirty() : false;
    const stateRepo = typeof state?.getStateRepo === 'function' ? state.getStateRepo() : 'unknown';

    return reply.send({
      version: VERSION,
      timestamp: new Date().toISOString(),
      github: {
        authenticated: typeof github?.isAuthenticated === 'function' ? github.isAuthenticated() : !!token,
        rateLimit,
      },
      state: {
        lastSync,
        pendingChanges: isDirty,
        stateRepo,
      },
      repos: {
        managed: managedRepos.length,
        list: managedRepos
          .filter((r: any) => r.name !== '*')
          .map((r: any) => `${r.owner}/${r.name}`),
      },
      gateway: gateway
        ? {
            available: gateway.available,
            appCount: gateway.appCount,
            toolCount: gateway.toolCount,
          }
        : { available: false },
    });
  });

  // TAEM missions (placeholder)
  app.get('/api/taem/missions', async (_req, reply) => {
    return reply.send({
      missions: [],
      note: 'TAEM mission integration is planned for a future release.',
    });
  });
}
