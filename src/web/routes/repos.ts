/**
 * Repository management routes
 *
 * GET  /api/repos              — list managed repos
 * GET  /api/repos/:owner/:repo — repo details
 * POST /api/repos              — add a repo
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';

export async function registerRepoRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { state, token } = config;

  const getManagedRepos = () => {
    if (typeof state?.getManagedRepos === 'function') return state.getManagedRepos();
    return [];
  };

  // List managed repos
  app.get('/api/repos', async (_req, reply) => {
    const repos = getManagedRepos();
    return reply.send({
      count: repos.length,
      repos: repos
        .filter((r: any) => r.name !== '*')
        .map((r: any) => ({
          owner: r.owner,
          name: r.name,
          fullName: `${r.owner}/${r.name}`,
          policies: r.policies ?? [],
        })),
    });
  });

  // Get repo details
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/repos/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    const managed = getManagedRepos();
    const entry = managed.find((r: any) => r.owner === owner && r.name === repo);

    return reply.send({
      owner,
      name: repo,
      fullName,
      managed: !!entry,
      policies: entry?.policies ?? [],
    });
  });

  // Add a repo
  app.post<{
    Body: { owner: string; name: string; policies?: string[] };
  }>('/api/repos', async (req, reply) => {
    const { owner, name, policies } = req.body;

    if (!owner || !name) {
      return reply.status(400).send({ error: 'owner and name are required' });
    }

    if (typeof state?.addManagedRepo === 'function') {
      state.addManagedRepo({ owner, name, policies: policies ?? ['default'] });
    }

    return reply.status(201).send({
      added: true,
      fullName: `${owner}/${name}`,
      policies: policies ?? ['default'],
    });
  });
}
