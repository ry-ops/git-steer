/**
 * git-fabric/cve inline connector
 *
 * Thin implementations of the @git-fabric/cve layer APIs,
 * designed to work inside git-steer without requiring the
 * @git-fabric/cve package as a dependency.
 *
 * When @git-fabric/cve is published to npm, these can be
 * replaced with direct imports. Until then, this connector
 * provides the same functionality inline.
 */

import type { FabricGitHubAdapter, FabricStateAdapter } from './adapter.js';

// ── Types ───────────────────────────────────────────────────────────────────

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'];

interface CveQueueEntry {
  id: string;
  ghsaId?: string;
  repo: string;
  ecosystem: string;
  affectedPackage: string;
  affectedVersion: string;
  patchedVersion: string;
  severity: Severity;
  cvssScore: number | null;
  summary: string;
  nvdUrl: string;
  detectedAt: string;
  status: 'pending' | 'pr_opened' | 'skipped' | 'error';
  prNumber?: number;
  prUrl?: string;
  processedAt?: string;
  skipReason?: string;
}

interface CveEnrichment {
  id: string;
  status: string;
  severity: string;
  score: number | null;
  description: string;
  published: string;
  references: string[];
  cwe: string | null;
}

interface TriagePlan {
  entry: CveQueueEntry;
  action: 'open_pr' | 'open_draft' | 'skip';
  reason: string;
}

interface PrResult {
  cveId: string;
  repo: string;
  action: 'pr_opened' | 'skipped' | 'error';
  prNumber?: number;
  prUrl?: string;
  reason?: string;
}

// ── Queue helpers ───────────────────────────────────────────────────────────

const QUEUE_FILE = 'state/cve-queue.jsonl';

function parseQueue(raw: string): Map<string, CveQueueEntry> {
  const map = new Map<string, CveQueueEntry>();
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const entry: CveQueueEntry = JSON.parse(trimmed);
      map.set(`${entry.id}::${entry.repo}`, entry);
    } catch { /* skip malformed */ }
  }
  return map;
}

function serialize(map: Map<string, CveQueueEntry>): string {
  return Array.from(map.values()).map((e) => JSON.stringify(e)).join('\n');
}

// ── Detection ───────────────────────────────────────────────────────────────

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'NPM', pip: 'PIP', go: 'GO', maven: 'MAVEN', cargo: 'RUST', composer: 'COMPOSER',
};

const MANIFEST_PATHS = [
  { path: 'package.json', ecosystem: 'npm' },
  { path: 'requirements.txt', ecosystem: 'pip' },
  { path: 'go.mod', ecosystem: 'go' },
  { path: 'Cargo.toml', ecosystem: 'cargo' },
] as const;

function normalizeSeverity(s: string): Severity {
  const upper = s?.toUpperCase() as Severity;
  return (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as Severity[]).includes(upper) ? upper : 'UNKNOWN';
}

function parseNpmDeps(content: string): Record<string, string> {
  try {
    const pkg = JSON.parse(content);
    return { ...pkg.dependencies, ...pkg.devDependencies };
  } catch { return {}; }
}

function parsePipDeps(content: string): Record<string, string> {
  const deps: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([A-Za-z0-9_\-.]+)\s*[>=<!]=?\s*(.+?)(?:\s*#.*)?$/);
    if (match) deps[match[1]] = match[2].trim();
    else {
      const nameOnly = trimmed.match(/^([A-Za-z0-9_\-.]+)/);
      if (nameOnly) deps[nameOnly[1]] = 'unknown';
    }
  }
  return deps;
}

function parseGoDeps(content: string): Record<string, string> {
  const deps: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const match = line.trim().match(/^require\s+(\S+)\s+(\S+)/) || line.trim().match(/^\s+(\S+)\s+(v[\d.]+)/);
    if (match) deps[match[1]] = match[2];
  }
  return deps;
}

function parseCargoDeps(content: string): Record<string, string> {
  const deps: Record<string, string> = {};
  let inDeps = false;
  for (const line of content.split('\n')) {
    if (line.match(/^\[(?:dev-)?dependencies\]/)) { inDeps = true; continue; }
    if (line.startsWith('[') && !line.match(/^\[(?:dev-)?dependencies\]/)) { inDeps = false; }
    if (!inDeps) continue;
    const match = line.match(/^(\S+)\s*=\s*"([^"]+)"/);
    if (match) deps[match[1]] = match[2];
  }
  return deps;
}

function parseDeps(content: string, ecosystem: string): Record<string, string> {
  switch (ecosystem) {
    case 'npm': return parseNpmDeps(content);
    case 'pip': return parsePipDeps(content);
    case 'go': return parseGoDeps(content);
    case 'cargo': return parseCargoDeps(content);
    default: return {};
  }
}

async function queryGhsa(
  ecosystem: string,
  packageName: string,
  token: string,
): Promise<{ ghsaId: string; cveId: string | null; summary: string; severity: string; cvssScore: number | null; firstPatchedVersion: string | null }[]> {
  const query = `
    query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
      securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 10, orderBy: { field: UPDATED_AT, direction: DESC }) {
        nodes {
          advisory { ghsaId cveId summary severity cvss { score } }
          firstPatchedVersion { identifier }
        }
      }
    }
  `;

  const res = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: { Authorization: `bearer ${token}`, 'Content-Type': 'application/json', 'User-Agent': 'git-steer-fabric/1.0' },
    body: JSON.stringify({ query, variables: { ecosystem: ECOSYSTEM_MAP[ecosystem] ?? ecosystem.toUpperCase(), package: packageName } }),
  });

  if (!res.ok) return [];
  const data = await res.json() as any;
  return (data?.data?.securityVulnerabilities?.nodes ?? []).map((n: any) => ({
    ghsaId: n.advisory.ghsaId,
    cveId: n.advisory.cveId ?? null,
    summary: n.advisory.summary,
    severity: n.advisory.severity,
    cvssScore: n.advisory.cvss?.score ?? null,
    firstPatchedVersion: n.firstPatchedVersion?.identifier ?? null,
  }));
}

export async function detect(
  repos: string[],
  severityThreshold: Severity,
  github: FabricGitHubAdapter,
): Promise<{ reposScanned: number; findings: CveQueueEntry[]; bySeverity: Record<string, number> }> {
  const thresholdIdx = SEVERITY_ORDER.indexOf(severityThreshold);
  const findings: CveQueueEntry[] = [];
  const seen = new Set<string>();

  for (const repoFull of repos) {
    const [owner, repo] = repoFull.split('/');

    for (const { path, ecosystem } of MANIFEST_PATHS) {
      const content = await github.getFileContent(owner, repo, path);
      if (!content) continue;

      const deps = parseDeps(content, ecosystem);

      for (const [pkgName, pkgVersion] of Object.entries(deps)) {
        if (!pkgName) continue;
        const advisories = await queryGhsa(ecosystem, pkgName, github.token);
        await new Promise((r) => setTimeout(r, 150));

        for (const adv of advisories) {
          const severity = normalizeSeverity(adv.severity);
          if (SEVERITY_ORDER.indexOf(severity) > thresholdIdx) continue;

          const key = `${adv.cveId ?? adv.ghsaId}::${repoFull}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id: adv.cveId ?? adv.ghsaId,
            ghsaId: adv.ghsaId,
            repo: repoFull,
            ecosystem,
            affectedPackage: pkgName,
            affectedVersion: pkgVersion,
            patchedVersion: adv.firstPatchedVersion ?? 'unknown',
            severity,
            cvssScore: adv.cvssScore,
            summary: adv.summary,
            nvdUrl: adv.cveId ? `https://nvd.nist.gov/vuln/detail/${adv.cveId}` : `https://github.com/advisories/${adv.ghsaId}`,
            detectedAt: new Date().toISOString(),
            status: 'pending',
          });
        }
      }
    }
  }

  const bySeverity: Record<string, number> = {};
  for (const s of SEVERITY_ORDER) bySeverity[s] = findings.filter((f) => f.severity === s).length;

  return { reposScanned: repos.length, findings, bySeverity };
}

// ── Intelligence ────────────────────────────────────────────────────────────

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export async function enrich(cveId: string, nvdApiKey?: string): Promise<CveEnrichment> {
  const headers: Record<string, string> = { 'User-Agent': 'git-steer-fabric/1.0' };
  if (nvdApiKey) headers['apiKey'] = nvdApiKey;

  const res = await fetch(`${NVD_API}?cveId=${encodeURIComponent(cveId)}`, { headers });
  if (res.status === 404) throw new Error(`CVE ${cveId} not found in NVD`);
  if (!res.ok) throw new Error(`NVD API error: ${res.status}`);

  const data = await res.json() as any;
  const item = data.vulnerabilities?.[0]?.cve;
  if (!item) throw new Error(`No data returned for ${cveId}`);

  const v31 = item.metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = item.metrics?.cvssMetricV30?.[0]?.cvssData;
  const score = v31?.baseScore ?? v30?.baseScore ?? null;
  const severity = v31?.baseSeverity ?? v30?.baseSeverity ?? 'UNKNOWN';

  return {
    id: item.id,
    status: item.vulnStatus,
    severity,
    score,
    description: item.descriptions?.find((d: any) => d.lang === 'en')?.value ?? 'No description available.',
    published: item.published,
    references: (item.references ?? []).slice(0, 5).map((r: any) => r.url),
    cwe: item.weaknesses?.[0]?.description?.find((d: any) => d.lang === 'en')?.value ?? null,
  };
}

// ── State ───────────────────────────────────────────────────────────────────

export async function enqueue(
  entries: CveQueueEntry[],
  state: FabricStateAdapter,
): Promise<{ added: number; duplicates: number }> {
  const raw = await state.read(QUEUE_FILE);
  const existing = parseQueue(raw ?? '');
  let added = 0, duplicates = 0;

  for (const entry of entries) {
    const key = `${entry.id}::${entry.repo}`;
    if (existing.has(key)) { duplicates++; } else { existing.set(key, entry); added++; }
  }

  await state.write(QUEUE_FILE, serialize(existing));
  return { added, duplicates };
}

export async function listQueue(
  state: FabricStateAdapter,
  opts: { status?: string; severityMin?: Severity; repo?: string; limit?: number } = {},
): Promise<{ total: number; entries: CveQueueEntry[] }> {
  const raw = await state.read(QUEUE_FILE);
  if (!raw) return { total: 0, entries: [] };

  const queue = parseQueue(raw);
  const status = opts.status ?? 'pending';
  const thresholdIdx = SEVERITY_ORDER.indexOf(opts.severityMin ?? 'LOW');

  let entries = Array.from(queue.values()).filter((e) => {
    if (status !== 'all' && e.status !== status) return false;
    if (opts.repo && e.repo !== opts.repo) return false;
    if (SEVERITY_ORDER.indexOf(e.severity) > thresholdIdx) return false;
    return true;
  });

  entries.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
  const limit = Math.max(1, opts.limit ?? 50);
  return { total: entries.length, entries: entries.slice(0, limit) };
}

export async function pending(state: FabricStateAdapter): Promise<CveQueueEntry[]> {
  const { entries } = await listQueue(state, { status: 'pending' });
  return entries;
}

export async function updateQueue(
  updates: { id: string; repo: string; status: string; prNumber?: number; prUrl?: string; skipReason?: string }[],
  state: FabricStateAdapter,
): Promise<{ updated: number }> {
  const raw = await state.read(QUEUE_FILE);
  const queue = parseQueue(raw ?? '');
  let updated = 0;

  for (const u of updates) {
    const key = `${u.id}::${u.repo}`;
    const existing = queue.get(key);
    if (!existing) continue;
    queue.set(key, { ...existing, status: u.status as CveQueueEntry['status'], prNumber: u.prNumber, prUrl: u.prUrl, skipReason: u.skipReason, processedAt: new Date().toISOString() });
    updated++;
  }

  await state.write(QUEUE_FILE, serialize(queue));
  return { updated };
}

export async function queueStats(state: FabricStateAdapter): Promise<{
  total: number;
  byStatus: Record<string, number>;
  pendingBySeverity: Record<string, number>;
  oldestPending: { id: string; repo: string; severity: string; detectedAt: string } | null;
  topRepos: { repo: string; pending: number }[];
}> {
  const raw = await state.read(QUEUE_FILE);
  if (!raw) return { total: 0, byStatus: {}, pendingBySeverity: {}, oldestPending: null, topRepos: [] };

  const entries = Array.from(parseQueue(raw).values());
  const byStatus = entries.reduce((acc, e) => ({ ...acc, [e.status]: (acc[e.status] ?? 0) + 1 }), {} as Record<string, number>);
  const pendingEntries = entries.filter((e) => e.status === 'pending');
  const pendingBySeverity: Record<string, number> = {};
  for (const s of SEVERITY_ORDER) pendingBySeverity[s] = pendingEntries.filter((e) => e.severity === s).length;

  const oldest = pendingEntries.sort((a, b) => new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime())[0];
  const byRepo = pendingEntries.reduce((acc, e) => ({ ...acc, [e.repo]: (acc[e.repo] ?? 0) + 1 }), {} as Record<string, number>);
  const topRepos = Object.entries(byRepo).sort(([, a], [, b]) => b - a).slice(0, 10).map(([repo, count]) => ({ repo, pending: count }));

  return {
    total: entries.length, byStatus, pendingBySeverity,
    oldestPending: oldest ? { id: oldest.id, repo: oldest.repo, severity: oldest.severity, detectedAt: oldest.detectedAt } : null,
    topRepos,
  };
}

// ── Decision ────────────────────────────────────────────────────────────────

export const DEFAULT_POLICY = {
  autoPrThreshold: 'HIGH' as Severity,
  maxPrsPerRun: 5,
  requirePatchedVersion: true,
};

export function triage(
  entries: CveQueueEntry[],
  policy: typeof DEFAULT_POLICY,
): TriagePlan[] {
  const sorted = [...entries].filter((e) => e.status === 'pending').sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || (b.cvssScore ?? 0) - (a.cvssScore ?? 0),
  );

  const plans: TriagePlan[] = [];
  let prCount = 0;

  for (const entry of sorted) {
    if (prCount >= policy.maxPrsPerRun) { plans.push({ entry, action: 'skip', reason: `PR cap reached (${policy.maxPrsPerRun})` }); continue; }
    if (policy.requirePatchedVersion && (!entry.patchedVersion || entry.patchedVersion === 'unknown')) { plans.push({ entry, action: 'skip', reason: 'No patched version available' }); continue; }
    if (SEVERITY_ORDER.indexOf(entry.severity) > SEVERITY_ORDER.indexOf(policy.autoPrThreshold)) { plans.push({ entry, action: 'skip', reason: `${entry.severity} below threshold ${policy.autoPrThreshold}` }); continue; }

    if (entry.severity === 'CRITICAL') { plans.push({ entry, action: 'open_pr', reason: 'CRITICAL — immediate PR' }); }
    else { plans.push({ entry, action: 'open_draft', reason: `${entry.severity} — draft PR` }); }
    prCount++;
  }

  return plans;
}

// ── Action ──────────────────────────────────────────────────────────────────

const SEVERITY_EMOJI: Record<string, string> = { CRITICAL: '\u{1F534}', HIGH: '\u{1F7E0}', MEDIUM: '\u{1F7E1}', LOW: '\u{1F7E2}' };

function buildPrBody(entry: CveQueueEntry): string {
  const emoji = SEVERITY_EMOJI[entry.severity] ?? '\u{26AB}';
  const scoreStr = entry.cvssScore !== null ? `${entry.cvssScore}/10` : 'N/A';

  return `## Security Fix: ${entry.id}

> This PR was opened automatically by [git-steer](https://github.com/ry-ops/git-steer) via [@git-fabric/cve](https://github.com/git-fabric/cve).

| Field | Value |
|-------|-------|
| **CVE** | [${entry.id}](${entry.nvdUrl}) |
| **Severity** | ${emoji} ${entry.severity} |
| **CVSS Score** | ${scoreStr} |
| **Package** | \`${entry.affectedPackage}\` @ \`${entry.affectedVersion}\` |
| **Patched Version** | \`${entry.patchedVersion}\` |

### Description

${entry.summary}

### Required Action

Upgrade \`${entry.affectedPackage}\` to \`${entry.patchedVersion}\` or later.

### Review Checklist

- [ ] Dependency upgraded
- [ ] Lockfile committed
- [ ] Tests pass

---
<!-- git-steer + git-fabric/cve | ${entry.id} | ${new Date().toISOString()} -->
`;
}

function prLabels(severity: string): string[] {
  const base = ['security', 'cve', 'git-fabric'];
  const map: Record<string, string[]> = {
    CRITICAL: ['severity:critical', 'priority:urgent'],
    HIGH: ['severity:high', 'priority:high'],
    MEDIUM: ['severity:medium'],
    LOW: ['severity:low'],
  };
  return [...base, ...(map[severity] ?? [])];
}

function updateNpmManifest(content: string, pkg: string, version: string): string | null {
  try {
    const json = JSON.parse(content);
    let changed = false;
    for (const section of ['dependencies', 'devDependencies', 'peerDependencies']) {
      if (json[section]?.[pkg]) { json[section][pkg] = `^${version}`; changed = true; }
    }
    return changed ? JSON.stringify(json, null, 2) + '\n' : null;
  } catch { return null; }
}

const ECOSYSTEM_MANIFEST: Record<string, string> = { npm: 'package.json', pip: 'requirements.txt', go: 'go.mod', cargo: 'Cargo.toml' };

export async function execute(
  plans: TriagePlan[],
  github: FabricGitHubAdapter,
  dryRun = false,
): Promise<PrResult[]> {
  const results: PrResult[] = [];

  for (const plan of plans) {
    if (plan.action === 'skip') { results.push({ cveId: plan.entry.id, repo: plan.entry.repo, action: 'skipped', reason: plan.reason }); continue; }
    if (dryRun) { results.push({ cveId: plan.entry.id, repo: plan.entry.repo, action: 'pr_opened', reason: `[DRY RUN] Would open ${plan.action === 'open_draft' ? 'draft ' : ''}PR` }); continue; }

    const [owner, repo] = plan.entry.repo.split('/');
    const branch = `security/${plan.entry.id.toLowerCase()}`;
    const title = `fix(security): ${plan.entry.id} \u2013 ${plan.entry.severity} in ${plan.entry.affectedPackage}`;

    try {
      const base = await github.getDefaultBranch(owner, repo);
      await github.createBranch(owner, repo, branch, base);

      // Commit actual dependency bump if possible
      const manifestPath = ECOSYSTEM_MANIFEST[plan.entry.ecosystem];
      if (manifestPath && plan.entry.patchedVersion !== 'unknown' && plan.entry.ecosystem === 'npm') {
        const content = await github.getFileContent(owner, repo, manifestPath);
        if (content) {
          const updated = updateNpmManifest(content, plan.entry.affectedPackage, plan.entry.patchedVersion);
          if (updated) {
            await github.commitFiles(owner, repo, {
              branch,
              message: `fix(security): upgrade ${plan.entry.affectedPackage} to ${plan.entry.patchedVersion}\n\nResolves ${plan.entry.id}`,
              files: [{ path: manifestPath, content: updated }],
            });
          }
        }
      }

      const pr = await github.createPullRequest(owner, repo, {
        title,
        body: buildPrBody(plan.entry),
        head: branch,
        base,
        draft: plan.action === 'open_draft',
        labels: prLabels(plan.entry.severity),
      });

      results.push({ cveId: plan.entry.id, repo: plan.entry.repo, action: 'pr_opened', prNumber: pr.number, prUrl: pr.html_url });
      await new Promise((r) => setTimeout(r, 500));
    } catch (err: unknown) {
      results.push({ cveId: plan.entry.id, repo: plan.entry.repo, action: 'error', reason: (err as Error).message });
    }
  }

  return results;
}
