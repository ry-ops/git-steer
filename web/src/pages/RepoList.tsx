import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import { api } from '../lib/api';
import { TrendBars } from './Dashboard';
import type { RecentScan, TrendData, AutoscanConfig, SeverityCounts } from '../lib/api';

interface RepoItem {
  owner: string;
  name: string;
  fullName: string;
  private: boolean;
  archived: boolean;
  language: string | null;
  pushedAt: string | null;
  managed: boolean;
}

interface RepoMeta {
  lastScan?: RecentScan;
  trend?: number[];
  autoscan?: AutoscanConfig;
}

export default function RepoList() {
  const navigate = useNavigate();
  const [repos, setRepos] = useState<RepoItem[]>([]);
  const [orgs, setOrgs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [orgFilter, setOrgFilter] = useState<string | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);
  const [repoMeta, setRepoMeta] = useState<Record<string, RepoMeta>>({});

  useEffect(() => {
    loadRepos();
  }, []);

  async function loadRepos() {
    try {
      const data = await api.repos.list();
      const repoList = Array.isArray(data) ? data : Array.isArray(data?.repos) ? data.repos : [];
      setRepos(repoList);
      setOrgs(data?.orgs ?? []);

      // Load recent scans to enrich repo cards
      try {
        const scans = await api.scans.recent(50);
        if (Array.isArray(scans)) {
          const meta: Record<string, RepoMeta> = {};
          // Group by repo, take latest
          scans.forEach((scan) => {
            const key = `${scan.owner}/${scan.repo}`;
            if (!meta[key] || new Date(scan.scanned_at) > new Date(meta[key].lastScan!.scanned_at)) {
              meta[key] = { ...meta[key], lastScan: scan };
            }
          });

          // Load trends and autoscan for managed repos (best-effort, parallel)
          const uniqueRepos = Object.keys(meta);
          const trendPromises = uniqueRepos.map(async (key) => {
            const [o, r] = key.split('/');
            try {
              const trend = await api.trends.get(o, r);
              if (trend?.points) {
                meta[key] = { ...meta[key], trend: trend.points };
              }
            } catch { /* trend not available */ }
          });
          const autoscanPromises = uniqueRepos.map(async (key) => {
            const [o, r] = key.split('/');
            try {
              const config = await api.autoscan.get(o, r);
              if (config) {
                meta[key] = { ...meta[key], autoscan: config };
              }
            } catch { /* autoscan not available */ }
          });

          await Promise.allSettled([...trendPromises, ...autoscanPromises]);
          setRepoMeta(meta);
        }
      } catch {
        // Recent scans API not available
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load repos');
    } finally {
      setLoading(false);
    }
  }

  async function handleScan(owner: string, name: string) {
    setScanning(`${owner}/${name}`);
    try {
      await api.cve.scan(owner, name);
      navigate(`/repos/${owner}/${name}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(null);
    }
  }

  const filtered = repos.filter(r => {
    if (r.archived) return false;
    if (orgFilter && r.owner !== orgFilter) return false;
    if (filter && !r.fullName.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="font-display font-bold text-3xl text-contrast">Repositories</h1>
          <p className="text-muted mt-1">{repos.length} repos across {orgs.length + 1} orgs</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <input
          type="text"
          placeholder="Filter repos..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 px-4 py-2 rounded-full border-2 border-border bg-base font-mono text-sm text-contrast placeholder:text-muted/50 focus:outline-none focus:border-accent transition-colors"
        />
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setOrgFilter(null)}
            className={`px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wide transition-colors ${
              !orgFilter ? 'bg-accent text-white' : 'bg-card text-muted hover:text-contrast'
            }`}
          >
            All
          </button>
          {orgs.map(org => (
            <button
              key={org}
              onClick={() => setOrgFilter(orgFilter === org ? null : org)}
              className={`px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wide transition-colors ${
                orgFilter === org ? 'bg-accent text-white' : 'bg-card text-muted hover:text-contrast'
              }`}
            >
              {org}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <Card className="border-critical/40 mb-6">
          <p className="text-critical font-semibold text-sm">{error}</p>
        </Card>
      )}

      {/* Loading */}
      {loading && (
        <div className="text-center py-16">
          <div className="inline-block w-8 h-8 border-4 border-border border-t-accent rounded-full animate-spin" />
          <p className="text-muted mt-4">Loading repositories...</p>
        </div>
      )}

      {/* Repo Grid */}
      {!loading && filtered.length === 0 && (
        <Card>
          <p className="text-muted text-center py-8">
            {filter ? 'No repos match your filter.' : 'No repositories found.'}
          </p>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map((r) => {
          const meta = repoMeta[r.fullName];
          const lastScan = meta?.lastScan;
          const counts = lastScan?.counts;
          const hasAlerts = counts && (counts.critical + counts.high + counts.medium + counts.low) > 0;

          return (
            <Card
              key={r.fullName}
              onClick={() => navigate(`/repos/${r.owner}/${r.name}`)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="min-w-0 flex-1">
                  <h3 className="font-mono text-sm font-semibold text-contrast truncate">
                    {r.fullName}
                  </h3>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {r.language && (
                      <span className="text-xs text-muted">{r.language}</span>
                    )}
                    {r.private && (
                      <span className="text-xs text-muted bg-card px-1.5 py-0.5 rounded">private</span>
                    )}
                    {r.pushedAt && (
                      <span className="text-xs text-muted">{formatRelative(r.pushedAt)}</span>
                    )}
                    {/* Auto-scan indicator */}
                    {meta?.autoscan?.enabled && (
                      <span className="inline-flex items-center gap-1 text-xs text-muted" title={`Auto-scan: ${meta.autoscan.schedule ?? 'enabled'}`}>
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {meta.autoscan.schedule ?? 'auto'}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Last scan info */}
              {lastScan && (
                <div className="mb-3">
                  <p className="text-xs text-muted mb-1.5">
                    Last scan: {formatRelative(lastScan.scanned_at)}
                  </p>
                  {hasAlerts && (
                    <div className="flex flex-wrap gap-1">
                      {counts!.critical > 0 && <Badge severity="CRITICAL" count={counts!.critical} />}
                      {counts!.high > 0 && <Badge severity="HIGH" count={counts!.high} />}
                      {counts!.medium > 0 && <Badge severity="MEDIUM" count={counts!.medium} />}
                      {counts!.low > 0 && <Badge severity="LOW" count={counts!.low} />}
                    </div>
                  )}
                  {!hasAlerts && (
                    <span className="text-xs text-safe font-semibold uppercase tracking-wide">Clean</span>
                  )}
                </div>
              )}

              {/* Trend sparkline */}
              {meta?.trend && meta.trend.length > 1 && (
                <div className="mb-3">
                  <TrendBars data={meta.trend} />
                </div>
              )}

              <Button
                variant="secondary"
                className="w-full text-xs"
                onClick={(e) => {
                  e.stopPropagation();
                  handleScan(r.owner, r.name);
                }}
              >
                {scanning === r.fullName ? 'Scanning...' : 'Scan for CVEs'}
              </Button>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function formatRelative(iso: string): string {
  try {
    const d = new Date(iso);
    const diff = Date.now() - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return iso;
  }
}
