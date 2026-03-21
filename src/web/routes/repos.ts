/**
 * Repository management routes
 *
 * GET  /api/repos              — list managed repos
 * GET  /api/repos/:owner/:repo — repo details
 * POST /api/repos              — add a repo
 */

import { Octokit } from 'octokit';
import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';

export async function registerRepoRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { state, token } = config;

  // Create an Octokit for GitHub API calls
  const octokit = token ? new Octokit({ auth: token }) : null;

  // List all repos — pulls from GitHub, enriched with managed status
  app.get('/api/repos', async (_req, reply) => {
    if (!octokit) {
      return reply.status(503).send({ error: 'No GitHub token configured' });
    }

    try {
      // Get user's repos
      const userRepos = await octokit.rest.repos.listForAuthenticatedUser({
        per_page: 100,
        sort: 'pushed',
        type: 'owner',
      });

      // Get orgs
      const orgs = await octokit.rest.orgs.listForAuthenticatedUser({ per_page: 50 });

      // Get repos for each org
      const orgRepos = [];
      for (const org of orgs.data) {
        try {
          const repos = await octokit.rest.repos.listForOrg({
            org: org.login,
            per_page: 100,
            sort: 'pushed',
          });
          orgRepos.push(...repos.data);
        } catch {
          // Skip orgs we don't have access to
        }
      }

      // Combine and dedupe
      const allRepos = [...userRepos.data, ...orgRepos];
      const seen = new Set<string>();
      const dedupedRepos = allRepos.filter(r => {
        const key = r.full_name;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

      // Get managed list for enrichment
      const managed = typeof state?.getManagedRepos === 'function'
        ? state.getManagedRepos().map((r: any) => `${r.owner}/${r.name}`)
        : [];

      const repos = dedupedRepos.map(r => ({
        owner: r.owner?.login ?? '',
        name: r.name,
        fullName: r.full_name,
        private: r.private,
        archived: r.archived,
        defaultBranch: r.default_branch ?? 'main',
        pushedAt: r.pushed_at,
        language: r.language,
        managed: managed.includes(r.full_name),
      }));

      return reply.send({
        count: repos.length,
        orgs: orgs.data.map(o => o.login),
        repos,
      });
    } catch (err: any) {
      return reply.status(500).send({ error: err.message });
    }
  });

  // Get repo details
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/repos/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    const managed = typeof state?.getManagedRepos === 'function' ? state.getManagedRepos() : [];
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
