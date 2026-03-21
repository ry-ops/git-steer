const BASE = '';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    throw new Error(`GET ${path} failed: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    throw new Error(`POST ${path} failed: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  repos: {
    list: () => get<Repo[]>('/api/repos'),
    get: (owner: string, repo: string) => get<Repo>(`/api/repos/${owner}/${repo}`),
    add: (body: { owner: string; repo: string }) => post<Repo>('/api/repos', body),
  },
  cve: {
    scan: (owner: string, repo: string) => post<ScanResult>('/api/cve/scan', { owner, repo }),
    results: (owner: string, repo: string) => get<ScanResult>(`/api/cve/results/${owner}/${repo}`),
    fix: (cveId: string, owner: string, repo: string) =>
      post<FixResult>('/api/cve/fix', { cve_id: cveId, owner, repo }),
    queue: () => get<QueueItem[]>('/api/cve/queue'),
  },
  status: () => get<StatusResponse>('/api/status'),
  health: () => get<{ status: string }>('/health'),
};

// ---- Types ----

export interface Repo {
  owner: string;
  repo: string;
  last_scan?: string;
  cve_counts?: SeverityCounts;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface CveEntry {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  package_name: string;
  installed_version: string;
  fixed_version?: string;
  description: string;
  nvd_url?: string;
  dismissed?: boolean;
}

export interface ScanResult {
  owner: string;
  repo: string;
  scanned_at: string;
  cves: CveEntry[];
  counts: SeverityCounts;
}

export interface FixResult {
  pr_url: string;
  cve_id: string;
  status: string;
}

export interface QueueItem {
  owner: string;
  repo: string;
  queued_at: string;
  status: string;
}

export interface StatusResponse {
  total_repos: number;
  open_cves: number;
  fixed_this_month: number;
  last_scan: string;
}
