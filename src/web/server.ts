/**
 * Fastify HTTP web server for git-steer
 *
 * Provides REST endpoints for repo management, CVE scanning,
 * and status monitoring. Runs alongside (not instead of) the MCP server.
 */

import { existsSync } from 'fs';
import { join } from 'path';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { GitHubClient } from '../github/client.js';
import { StateManager } from '../state/manager.js';
import type { GatewayHandle } from '../fabric/gateway.js';
import { registerRepoRoutes } from './routes/repos.js';
import { registerCveRoutes } from './routes/cve.js';
import { registerVexRoutes } from './routes/vex.js';
import { registerSbomRoutes } from './routes/sbom.js';
import { registerStatusRoutes } from './routes/status.js';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { version: VERSION } = require('../../package.json');

export interface WebServerConfig {
  github: GitHubClient;
  state: StateManager;
  gateway?: GatewayHandle;
  port?: number;
  token?: string;
}

export async function startWebServer(config: WebServerConfig): Promise<FastifyInstance> {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: true });

  // Decorate the instance with shared deps so routes can access them
  app.decorate('github', config.github);
  app.decorate('state', config.state);
  app.decorate('gateway', config.gateway ?? null);
  app.decorate('VERSION', VERSION);

  // Register route modules
  await registerRepoRoutes(app, config);
  await registerCveRoutes(app, config);
  await registerVexRoutes(app, config);
  await registerSbomRoutes(app, config);
  await registerStatusRoutes(app, config);

  // Serve static frontend if web-dist/ exists (Docker build)
  const webDistPath = join(process.cwd(), 'web-dist');
  if (existsSync(webDistPath)) {
    await app.register(fastifyStatic, {
      root: webDistPath,
      prefix: '/',
      wildcard: false,
    });
    // SPA fallback — serve index.html for all non-API routes
    app.setNotFoundHandler((_req, reply) => {
      return reply.sendFile('index.html', webDistPath);
    });
    console.log(`[git-steer] Serving frontend from ${webDistPath}`);
  }

  const port = config.port ?? 4300;
  await app.listen({ port, host: '0.0.0.0' });

  console.log(`[git-steer] Web server listening on http://0.0.0.0:${port}`);
  console.log(`[git-steer]   Repos    : http://localhost:${port}/api/repos`);
  console.log(`[git-steer]   CVE      : http://localhost:${port}/api/cve/queue`);
  console.log(`[git-steer]   Scans    : http://localhost:${port}/api/scans/recent`);
  console.log(`[git-steer]   VEX      : http://localhost:${port}/api/vex/:owner/:repo`);
  console.log(`[git-steer]   SBOM     : http://localhost:${port}/api/sbom/:owner/:repo`);
  console.log(`[git-steer]   Trends   : http://localhost:${port}/api/trends/:owner/:repo`);
  console.log(`[git-steer]   Status   : http://localhost:${port}/api/status`);
  console.log(`[git-steer]   Health   : http://localhost:${port}/health`);

  return app;
}
