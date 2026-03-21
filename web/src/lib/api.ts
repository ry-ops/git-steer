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

async function del<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`DELETE ${path} failed: ${res.status} ${res.statusText}`);
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
    fixAll: (owner: string, repo: string) => post<FixAllResult>('/api/cve/fix-all', { owner, repo }),
    verify: (owner: string, repo: string) => post<VerifyResult>(`/api/cve/verify/${owner}/${repo}`),
  },
  scans: {
    recent: (limit = 10) => get<RecentScan[]>(`/api/scans/recent?limit=${limit}`),
    get: (id: string) => get<ScanDetail>(`/api/scans/${id}`),
  },
  vex: {
    list: (owner: string, repo: string) => get<VexEntry[]>(`/api/vex/${owner}/${repo}`),
    set: (owner: string, repo: string, body: VexSetBody) => post<VexEntry>(`/api/vex/${owner}/${repo}`, body),
    remove: (owner: string, repo: string, cveId: string) => del<{ ok: boolean }>(`/api/vex/${owner}/${repo}/${cveId}`),
  },
  trends: {
    get: (owner: string, repo: string) => get<TrendData>(`/api/trends/${owner}/${repo}`),
  },
  sbom: {
    get: (owner: string, repo: string) => get<unknown>(`/api/sbom/${owner}/${repo}`),
    generate: (owner: string, repo: string) => post<unknown>(`/api/sbom/${owner}/${repo}`),
  },
  autoscan: {
    get: (owner: string, repo: string) => get<AutoscanConfig>(`/api/autoscan/${owner}/${repo}`),
    set: (owner: string, repo: string, schedule: string) => post<AutoscanConfig>(`/api/autoscan/${owner}/${repo}`, { schedule }),
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
  vex?: VexEntry;
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

export interface FixAllResult {
  total: number;
  fixed: number;
  no_fix: number;
  failed: number;
  details: Array<{ cve_id: string; status: string; pr_url?: string }>;
}

export interface VerifyResult {
  status: string;
  before: SeverityCounts;
  after: SeverityCounts;
  scan_id?: string;
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

export type VexStatus = 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
export type VexJustification =
  | 'component_not_present'
  | 'vulnerable_code_not_reachable'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'vulnerable_code_not_in_execute_path'
  | 'inline_mitigations_already_exist';

export interface VexEntry {
  cve_id: string;
  status: VexStatus;
  justification?: VexJustification;
  detail?: string;
  updated_at?: string;
}

export interface VexSetBody {
  cve_id: string;
  status: VexStatus;
  justification?: VexJustification;
  detail?: string;
}

export interface RecentScan {
  id: string;
  owner: string;
  repo: string;
  scanned_at: string;
  status: 'scanning' | 'complete' | 'verified' | 'failed';
  counts: SeverityCounts;
}

export interface ScanDetail extends RecentScan {
  cves: CveEntry[];
}

export interface TrendData {
  owner: string;
  repo: string;
  points: number[];
}

export interface AutoscanConfig {
  enabled: boolean;
  schedule?: 'daily' | 'weekly';
}
