/**
 * SBOM (Software Bill of Materials) routes — CycloneDX 1.5
 *
 * GET  /api/sbom/:owner/:repo  — returns latest SBOM snapshot
 * POST /api/sbom/:owner/:repo  — generates new SBOM from repo manifests + lockfiles
 *
 * Per ADR-004 C-004-002: SBOMs are CycloneDX, carry generatedAt + sourceSha,
 * and provide the component inventory (by PURL) that VEX statements bind to.
 */

import crypto from 'crypto';
import type { Octokit } from 'octokit';
import type { FastifyInstance } from 'fastify';
import type { WebServerConfig } from '../server.js';
import { getRedis, KEYS } from '../redis.js';

// ── CycloneDX 1.5 types (subset) ──────────────────────────────────────

export interface CycloneDxComponent {
  type: 'library';
  name: string;
  version: string;
  purl: string;
  scope: 'required' | 'optional';
  properties?: { name: string; value: string }[];
}

export interface CycloneDxBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
    component: { type: 'application'; name: string; 'bom-ref': string };
    properties: { name: string; value: string }[];
  };
  components: CycloneDxComponent[];
}

/** Stored snapshot wraps the CycloneDX doc with the ADR-required fields. */
export interface SbomSnapshot {
  repo: string;
  format: 'CycloneDX';
  specVersion: '1.5';
  generatedAt: string; // ADR-004 C-004-002
  sourceSha: string;   // ADR-004 C-004-002
  tool: string;
  componentCount: number;
  bom: CycloneDxBom;
}

// ── PURL helpers ──────────────────────────────────────────────────────

/** package-url encode a component name (handles npm scopes, etc). */
function purl(ecosystem: 'npm' | 'golang' | 'pypi', name: string, version: string): string {
  const v = version.replace(/^[\^~>=<\s]+/, '').trim() || '*';
  if (ecosystem === 'npm') {
    // scoped names (@scope/name): encode @ and each path segment, keeping the
    // namespace separator. Per-segment encoding avoids partial-escaping bugs.
    const enc = name.startsWith('@')
      ? '%40' + name.slice(1).split('/').map(encodeURIComponent).join('/')
      : encodeURIComponent(name);
    return `pkg:npm/${enc}@${v}`;
  }
  if (ecosystem === 'golang') return `pkg:golang/${name}@${v}`;
  return `pkg:pypi/${name.toLowerCase()}@${v}`;
}

// ── SBOM builder (pure-ish; testable in isolation) ────────────────────

export async function buildSbom(octokit: Octokit, owner: string, repo: string): Promise<SbomSnapshot> {
  // Resolve the default-branch HEAD sha so the SBOM is pinned to a commit.
  let sourceSha = 'unknown';
  let defaultBranch = 'main';
  try {
    const { data: repoData } = await octokit.rest.repos.get({ owner, repo });
    defaultBranch = repoData.default_branch;
    const { data: branch } = await octokit.rest.repos.getBranch({ owner, repo, branch: defaultBranch });
    sourceSha = branch.commit.sha;
  } catch { /* leave 'unknown' */ }

  // Prefer GitHub's native dependency-graph SBOM (SPDX): the full transitive
  // graph across ALL manifests (monorepo subdirs included), maintained by
  // GitHub. Falls back to local manifest/lockfile parsing if unavailable.
  let components = await componentsFromDependencyGraph(octokit, owner, repo);
  let inventorySource = 'github-dependency-graph';
  if (!components.length) {
    components = await componentsFromManifests(octokit, owner, repo, sourceSha);
    inventorySource = 'manifest-scan';
  }

  const generatedAt = new Date().toISOString();
  const bom: CycloneDxBom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: generatedAt,
      tools: [{ vendor: 'ry-ops', name: 'git-steer', version: '0.3.0' }],
      component: { type: 'application', name: `${owner}/${repo}`, 'bom-ref': `${owner}/${repo}@${sourceSha}` },
      properties: [
        { name: 'git:sourceSha', value: sourceSha },
        { name: 'git:defaultBranch', value: defaultBranch },
        { name: 'git-steer:inventorySource', value: inventorySource },
      ],
    },
    components,
  };

  return {
    repo: `${owner}/${repo}`,
    format: 'CycloneDX',
    specVersion: '1.5',
    generatedAt,
    sourceSha,
    tool: 'git-steer',
    componentCount: components.length,
    bom,
  };
}

/** Pull GitHub's dependency-graph SBOM (SPDX) and convert to CycloneDX components. */
async function componentsFromDependencyGraph(octokit: Octokit, owner: string, repo: string): Promise<CycloneDxComponent[]> {
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/dependency-graph/sbom', { owner, repo });
    const packages: any[] = (data as any)?.sbom?.packages ?? [];
    const components: CycloneDxComponent[] = [];
    const seen = new Set<string>();
    for (const p of packages) {
      const purlRef = (p.externalRefs ?? []).find((r: any) => r.referenceType === 'purl');
      if (!purlRef?.referenceLocator) continue; // skip the self/root package (no purl)
      const componentPurl: string = purlRef.referenceLocator;
      if (seen.has(componentPurl)) continue;
      seen.add(componentPurl);
      components.push({
        type: 'library',
        name: p.name ?? componentPurl,
        version: p.versionInfo ?? '*',
        purl: componentPurl,
        scope: 'required',
        properties: [{ name: 'spdxId', value: p.SPDXID ?? '' }],
      });
    }
    return components;
  } catch {
    return []; // dependency graph not enabled / no permission → fall back
  }
}

/** Fallback: parse manifests + lockfiles directly (root-level only). */
async function componentsFromManifests(octokit: Octokit, owner: string, repo: string, sourceSha: string): Promise<CycloneDxComponent[]> {
  const readFile = async (path: string): Promise<string | null> => {
    try {
      const { data } = await octokit.rest.repos.getContent({ owner, repo, path, ref: sourceSha !== 'unknown' ? sourceSha : undefined });
      if ('content' in data && data.content) return Buffer.from(data.content, 'base64').toString('utf8');
    } catch { /* missing */ }
    return null;
  };

  const components: CycloneDxComponent[] = [];
  const seen = new Set<string>();
  const add = (c: CycloneDxComponent) => {
    if (seen.has(c.purl)) return;
    seen.add(c.purl);
    components.push(c);
  };

  // ── npm: prefer package-lock.json (resolved + transitive), else package.json ──
  const lock = await readFile('package-lock.json');
  if (lock) {
    try {
      const parsed = JSON.parse(lock);
      // lockfile v2/v3: `packages` keyed by install path; "" is the root project.
      const pkgs: Record<string, any> = parsed.packages ?? {};
      for (const [installPath, meta] of Object.entries(pkgs)) {
        if (!installPath || !meta?.version) continue; // skip root + link entries
        const name = installPath.split('node_modules/').pop() as string;
        add({
          type: 'library',
          name,
          version: meta.version,
          purl: purl('npm', name, meta.version),
          scope: meta.dev ? 'optional' : 'required',
          properties: [{ name: 'ecosystem', value: 'npm' }, { name: 'resolved-from', value: 'package-lock.json' }],
        });
      }
    } catch { /* fall through to package.json */ }
  }
  if (!seen.size) {
    const pkgJson = await readFile('package.json');
    if (pkgJson) {
      try {
        const parsed = JSON.parse(pkgJson);
        for (const [name, version] of Object.entries(parsed.dependencies ?? {})) {
          add({ type: 'library', name, version: String(version), purl: purl('npm', name, String(version)), scope: 'required', properties: [{ name: 'ecosystem', value: 'npm' }] });
        }
        for (const [name, version] of Object.entries(parsed.devDependencies ?? {})) {
          add({ type: 'library', name, version: String(version), purl: purl('npm', name, String(version)), scope: 'optional', properties: [{ name: 'ecosystem', value: 'npm' }] });
        }
      } catch { /* ignore */ }
    }
  }

  // ── Go: go.mod require block ──
  const goMod = await readFile('go.mod');
  if (goMod) {
    const block = goMod.match(/require\s*\(([\s\S]*?)\)/);
    const lines = block
      ? block[1].split('\n')
      : goMod.split('\n').filter((l) => l.trim().startsWith('require '));
    for (const raw of lines) {
      const line = raw.replace(/^\s*require\s+/, '').replace(/\/\/.*$/, '').trim();
      if (!line) continue;
      const [name, version] = line.split(/\s+/);
      if (name && version) {
        add({ type: 'library', name, version, purl: purl('golang', name, version), scope: 'required', properties: [{ name: 'ecosystem', value: 'go' }] });
      }
    }
  }

  // ── Python: requirements.txt ──
  const reqTxt = await readFile('requirements.txt');
  if (reqTxt) {
    for (const line of reqTxt.split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#') || t.startsWith('-')) continue;
      const m = t.match(/^([a-zA-Z0-9_.-]+)\s*([=<>!~]=?\s*[^;]+)?/);
      if (m) {
        const version = (m[2] ?? '').replace(/^\s*==\s*/, '').trim() || '*';
        add({ type: 'library', name: m[1], version, purl: purl('pypi', m[1], version), scope: 'required', properties: [{ name: 'ecosystem', value: 'pip' }] });
      }
    }
  }

  return components;
}

// ── Routes ────────────────────────────────────────────────────────────

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
      const snapshot = await buildSbom(github.getOctokit(), owner, repo);

      const redis = await getRedis();
      await redis.set(KEYS.sbom(fullName), JSON.stringify(snapshot));

      return reply.status(201).send(snapshot);
    } catch (err: any) {
      return reply.status(500).send({ error: `Failed to generate SBOM: ${err.message}` });
    }
  });
}
