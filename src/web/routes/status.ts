/**
 * Health and status routes
 *
 * GET /health            — health check
 * GET /api/status        — git-steer status (rate limits, state sync, etc.)
 * GET /api/taem/missions — list TAEM missions (future)
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { version: VERSION } = require('../../../package.json');

export async function registerStatusRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { github, state, gateway } = config;

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
      rateLimit = await github.getRateLimit();
    } catch {
      // Non-fatal
    }

    const managedRepos = state.getManagedRepos();
    const recentAudit = state.getRecentAudit(10);
    const scheduledJobs = state.getScheduledJobs();
    const metrics = state.getMetrics();

    return reply.send({
      version: VERSION,
      timestamp: new Date().toISOString(),
      github: {
        authenticated: github.isAuthenticated(),
        rateLimit: rateLimit
          ? {
              core: rateLimit.buckets['core'],
              graphql: rateLimit.buckets['graphql'],
              warnings: rateLimit.warnings,
            }
          : null,
      },
      state: {
        lastSync: state.getLastSync(),
        pendingChanges: state.isDirty(),
        stateRepo: state.getStateRepo(),
      },
      repos: {
        managed: managedRepos.length,
        list: managedRepos
          .filter((r) => r.name !== '*')
          .map((r) => `${r.owner}/${r.name}`),
      },
      gateway: gateway
        ? {
            available: gateway.available,
            appCount: gateway.appCount,
            toolCount: gateway.toolCount,
          }
        : { available: false },
      security: {
        totalCves: metrics.totalCves,
        fixedCves: metrics.fixedCves,
        fixRate: metrics.fixRate,
        avgMttrHours: metrics.avgMttr,
      },
      jobs: {
        scheduled: scheduledJobs.map((j) => ({
          name: j.name,
          cron: j.schedule.cron,
          action: j.schedule.action,
        })),
      },
      recentAudit,
    });
  });

  // TAEM missions (placeholder for future integration)
  app.get('/api/taem/missions', async (_req, reply) => {
    return reply.send({
      missions: [],
      note: 'TAEM mission integration is planned for a future release.',
    });
  });
}
