/**
 * SBOM (Software Bill of Materials) routes
 *
 * GET  /api/sbom/:owner/:repo  — returns latest SBOM snapshot
 * POST /api/sbom/:owner/:repo  — generates new SBOM from repo manifests
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import { getRedis, KEYS } from '../redis.js';

export interface SbomPackage {
  name: string;
  version: string;
  ecosystem: string;
  scope?: 'runtime' | 'dev';
  license?: string;
}

export interface SbomSnapshot {
  repo: string;
  generated_at: string;
  tool: string;
  packages: SbomPackage[];
  total: number;
}

export async function registerSbomRoutes(app: FastifyInstance, config: WebServerConfig): Promise<void> {
  const { github } = config;

  // Get latest SBOM
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/sbom/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    try {
      const redis = await getRedis();
      const raw = await redis.get(KEYS.sbom(fullName));

      if (!raw) {
        return reply.status(404).send({
          error: 'No SBOM snapshot found. POST to generate one.',
          repo: fullName,
        });
      }

      return reply.send(JSON.parse(raw));
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch SBOM: ${err.message}` });
    }
  });

  // Generate new SBOM
  app.post<{
    Params: { owner: string; repo: string };
  }>('/api/sbom/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    try {
      const octokit = github.getOctokit();
      const packages: SbomPackage[] = [];

      // Try package.json (Node/npm)
      try {
        const { data } = await octokit.rest.repos.getContent({ owner, repo, path: 'package.json' });
        if ('content' in data && data.content) {
          const pkgJson = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8'));

          for (const [name, version] of Object.entries(pkgJson.dependencies ?? {})) {
            packages.push({ name, version: String(version), ecosystem: 'npm', scope: 'runtime' });
          }
          for (const [name, version] of Object.entries(pkgJson.devDependencies ?? {})) {
            packages.push({ name, version: String(version), ecosystem: 'npm', scope: 'dev' });
          }
        }
      } catch { /* no package.json */ }

      // Try go.mod (Go)
      try {
        const { data } = await octokit.rest.repos.getContent({ owner, repo, path: 'go.mod' });
        if ('content' in data && data.content) {
          const goMod = Buffer.from(data.content, 'base64').toString('utf8');
          const requireBlock = goMod.match(/require\s*\(([\s\S]*?)\)/);
          if (requireBlock) {
            const lines = requireBlock[1].split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('//'));
            for (const line of lines) {
              const parts = line.split(/\s+/);
              if (parts.length >= 2) {
                packages.push({ name: parts[0], version: parts[1], ecosystem: 'go' });
              }
            }
          }
        }
      } catch { /* no go.mod */ }

      // Try requirements.txt (Python)
      try {
        const { data } = await octokit.rest.repos.getContent({ owner, repo, path: 'requirements.txt' });
        if ('content' in data && data.content) {
          const reqTxt = Buffer.from(data.content, 'base64').toString('utf8');
          for (const line of reqTxt.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*([=<>!~]+\s*.*)?$/);
            if (match) {
              packages.push({
                name: match[1],
                version: match[2]?.replace(/^\s*==\s*/, '') ?? '*',
                ecosystem: 'pip',
              });
            }
          }
        }
      } catch { /* no requirements.txt */ }

      const snapshot: SbomSnapshot = {
        repo: fullName,
        generated_at: new Date().toISOString(),
        tool: 'git-steer',
        packages,
        total: packages.length,
      };

      // Store in Redis
      const redis = await getRedis();
      await redis.set(KEYS.sbom(fullName), JSON.stringify(snapshot));

      return reply.status(201).send(snapshot);
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to generate SBOM: ${err.message}` });
    }
  });
}
