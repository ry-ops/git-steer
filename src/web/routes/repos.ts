/**
 * Repository management routes
 *
 * GET  /api/repos              — list managed repos (from state manager)
 * GET  /api/repos/:owner/:repo — repo details + last scan info
 * POST /api/repos              — add a repo to managed list
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';

export async function registerRepoRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { github, state } = config;

  // List managed repos
  app.get('/api/repos', async (_req, reply) => {
    const repos = state.getManagedRepos();
    return reply.send({
      count: repos.length,
      repos: repos.map((r) => ({
        owner: r.owner,
        name: r.name,
        fullName: `${r.owner}/${r.name}`,
        policies: r.policies,
      })),
    });
  });

  // Get repo details + last scan info
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/repos/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    const managed = state.getManagedRepos();
    const entry = managed.find((r) => r.owner === owner && r.name === repo);

    if (!entry) {
      return reply.status(404).send({ error: 'Repo not in managed list', fullName });
    }

    // Pull last sweep timestamp from state cache
    const lastSwept = state.getLastSweptAt(fullName);

    // Pull recent audit entries for this repo
    const recentAudit = state.getRecentAudit(50)
      .filter((a) => a.repo === fullName)
      .slice(-10);

    // Pull RFCs for this repo
    const rfcs = state.getRfcs({ repo: fullName });

    return reply.send({
      owner,
      name: repo,
      fullName,
      policies: entry.policies,
      lastSwept,
      rfcs: rfcs.map((r) => ({
        issueNumber: r.issueNumber,
        issueUrl: r.issueUrl,
        severity: r.severity,
        status: r.status,
        vulnerabilities: r.vulnerabilities.length,
        prNumber: r.prNumber,
        prUrl: r.prUrl,
      })),
      recentAudit,
    });
  });

  // Add a repo to managed list
  app.post<{
    Body: { owner: string; name: string; policies?: string[] };
  }>('/api/repos', async (req, reply) => {
    const { owner, name, policies } = req.body;

    if (!owner || !name) {
      return reply.status(400).send({ error: 'owner and name are required' });
    }

    // Check it's not already managed
    const existing = state.getManagedRepos().find(
      (r) => r.owner === owner && r.name === name,
    );
    if (existing) {
      return reply.status(409).send({
        error: 'Repo already managed',
        fullName: `${owner}/${name}`,
      });
    }

    state.addManagedRepo({
      owner,
      name,
      policies: policies ?? ['default'],
    });

    return reply.status(201).send({
      added: true,
      fullName: `${owner}/${name}`,
      policies: policies ?? ['default'],
    });
  });
}
