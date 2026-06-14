/**
 * VEX (Vulnerability Exploitability eXchange) management routes — OpenVEX 0.2.0
 *
 * GET    /api/vex/:owner/:repo           — list all VEX entries for a repo
 * GET    /api/vex/:owner/:repo/openvex   — export entries as an OpenVEX document
 * POST   /api/vex/:owner/:repo           — create/update VEX entry for a CVE
 * DELETE /api/vex/:owner/:repo/:cveId    — remove VEX entry
 *
 * Per ADR-004 C-004-003: status ∈ {not_affected, affected, fixed,
 * under_investigation}. `not_affected` REQUIRES an OpenVEX justification;
 * `affected` REQUIRES an action_statement. Entries link to an SBOM component
 * by PURL (C-004-004) so each suppression is traceable to a component version.
 */

import crypto from 'crypto';
import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import { getRedis, KEYS } from '../redis.js';
import { validateVexInput, toOpenVex } from '../../core/vex.js';
import type { VexStatus, VexJustification, VexEntry, VexInput } from '../../core/vex.js';

// Canonical VEX vocabulary/validation/serialization lives in core/vex.ts so
// the web (Redis) and MCP (git-steer-state) stores share one definition.
export { validateVexInput, toOpenVex };
export type { VexStatus, VexJustification, VexEntry, VexInput };

// ── Routes ────────────────────────────────────────────────────────────

export async function registerVexRoutes(app: FastifyInstance, _config: WebServerConfig): Promise<void> {

  const loadEntries = async (fullName: string): Promise<VexEntry[]> => {
    const redis = await getRedis();
    const members = await redis.sMembers(KEYS.vexList(fullName));
    const entries: VexEntry[] = [];
    for (const cveId of members) {
      const raw = await redis.get(KEYS.vex(fullName, cveId));
      if (raw) {
        try { entries.push(JSON.parse(raw) as VexEntry); } catch { /* skip corrupt */ }
      }
    }
    entries.sort((a, b) => b.created_at.localeCompare(a.created_at));
    return entries;
  };

  // List all VEX entries for a repo
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/vex/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;
    try {
      const entries = await loadEntries(fullName);
      return reply.send({ repo: fullName, count: entries.length, entries });
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to fetch VEX entries: ${err.message}` });
    }
  });

  // Export VEX entries as an OpenVEX document
  app.get<{
    Params: { owner: string; repo: string };
  }>('/api/vex/:owner/:repo/openvex', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;
    try {
      const entries = await loadEntries(fullName);
      const doc = toOpenVex(
        fullName,
        entries,
        `https://git-steer.ry-ops.dev/vex/${fullName}/${crypto.randomUUID()}`,
        new Date().toISOString(),
      );
      return reply.header('content-type', 'application/json').send(doc);
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to export OpenVEX: ${err.message}` });
    }
  });

  // Create or update a VEX entry
  app.post<{
    Params: { owner: string; repo: string };
    Body: VexInput & { impact_statement?: string; detail?: string; updated_by?: string };
  }>('/api/vex/:owner/:repo', async (req, reply) => {
    const { owner, repo } = req.params;
    const fullName = `${owner}/${repo}`;
    const body = req.body;

    const error = validateVexInput(body);
    if (error) return reply.status(400).send({ error });

    try {
      const redis = await getRedis();
      const entry: VexEntry = {
        cve_id: body.cve_id!,
        repo: fullName,
        product_purl: body.product_purl,
        status: body.status as VexStatus,
        justification: body.justification as VexJustification | undefined,
        action_statement: body.action_statement,
        impact_statement: body.impact_statement,
        detail: body.detail,
        created_at: new Date().toISOString(),
        updated_by: body.updated_by ?? 'web',
      };

      await redis.set(KEYS.vex(fullName, entry.cve_id), JSON.stringify(entry));
      await redis.sAdd(KEYS.vexList(fullName), entry.cve_id);

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
