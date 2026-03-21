/**
 * VEX (Vulnerability Exploitability eXchange) management routes
 *
 * GET    /api/vex/:owner/:repo          — list all VEX entries for a repo
 * POST   /api/vex/:owner/:repo          — create/update VEX entry for a CVE
 * DELETE /api/vex/:owner/:repo/:cveId   — remove VEX entry
 */

import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import { getRedis, KEYS } from '../redis.js';

export interface VexEntry {
  cve_id: string;
  repo: string;
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
  justification?:
    | 'component_not_present'
    | 'vulnerable_code_not_reachable'
    | 'vulnerable_code_cannot_be_controlled_by_adversary'
    | 'inline_mitigations_already_exist';
  detail?: string;
  created_at: string;
  updated_by: string;
}

const VALID_STATUSES = ['not_affected', 'affected', 'fixed', 'under_investigation'] as const;
const VALID_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_reachable',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const;

export async function registerVexRoutes(app: FastifyInstance, _config: WebServerConfig): Promise<void> {

  // List all VEX entries for a repo
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/vex/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;

    try {
      const redis = await getRedis();
      const members = await redis.sMembers(KEYS.vexList(fullName));
      const entries: VexEntry[] = [];

      for (const cveId of members) {
        const raw = await redis.get(KEYS.vex(fullName, cveId));
        if (raw) {
          try {
            entries.push(JSON.parse(raw) as VexEntry);
          } catch { /* skip corrupt */ }
        }
      }

      // Sort newest first
      entries.sort((a, b) => b.created_at.localeCompare(a.created_at));

      return reply.send({
        repo: fullName,
        count: entries.length,
        entries,
      });
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch VEX entries: ${err.message}` });
    }
  });

  // Create or update a VEX entry
  app.post<{
    Params: { owner: string; repo: string };
    Body: {
      cve_id: string;
      status: VexEntry['status'];
      justification?: VexEntry['justification'];
      detail?: string;
      updated_by?: string;
    };
  }>('/api/vex/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const { cve_id, status, justification, detail, updated_by } = req.body;
    const fullName = `${owner}/${repo}`;

    if (!cve_id) {
      return reply.status(400).send({ error: 'cve_id is required' });
    }
    if (!status || !VALID_STATUSES.includes(status)) {
      return reply.status(400).send({
        error: `status must be one of: ${VALID_STATUSES.join(', ')}`,
      });
    }
    if (justification && !VALID_JUSTIFICATIONS.includes(justification)) {
      return reply.status(400).send({
        error: `justification must be one of: ${VALID_JUSTIFICATIONS.join(', ')}`,
      });
    }

    try {
      const redis = await getRedis();
      const entry: VexEntry = {
        cve_id,
        repo: fullName,
        status,
        justification,
        detail,
        created_at: new Date().toISOString(),
        updated_by: updated_by ?? 'web',
      };

      await redis.set(KEYS.vex(fullName, cve_id), JSON.stringify(entry));
      await redis.sAdd(KEYS.vexList(fullName), cve_id);

      return reply.status(201).send({ created: true, entry });
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to save VEX entry: ${err.message}` });
    }
  });

  // Delete a VEX entry
  app.delete<{
    Params: { owner: string; repo: string; cveId: string };
  }>('/api/vex/:owner/:repo/:cveId', async (req, reply) => {
    const { owner, repo, cveId } = req.params;
    const fullName = `${owner}/${repo}`;

    try {
      const redis = await getRedis();
      const existed = await redis.del(KEYS.vex(fullName, cveId));
      await redis.sRem(KEYS.vexList(fullName), cveId);

      if (!existed) {
        return reply.status(404).send({ error: 'VEX entry not found', cve_id: cveId, repo: fullName });
      }

      return reply.send({ deleted: true, cve_id: cveId, repo: fullName });
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to delete VEX entry: ${err.message}` });
    }
  });
}
