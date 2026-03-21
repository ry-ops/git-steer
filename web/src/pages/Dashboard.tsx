import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import { api } from '../lib/api';
import type { StatusResponse, QueueItem } from '../lib/api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [s, q] = await Promise.all([api.status(), api.cve.queue().catch(() => ({ queue: [] }))]);
        setStatus(s);
        // Handle both array and { queue: [...] } response shapes
        setQueue(Array.isArray(q) ? q : Array.isArray(q?.queue) ? q.queue : []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="animate-fade-in">
      {/* Hero Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6 mb-10">
        <div className="flex items-center gap-4">
          <img
            src="/steer-mascot.svg"
            alt="git-steer mascot"
            className="w-16 h-16 sm:w-20 sm:h-20"
            onError={(e) => {
              (e.target as HTMLImageElement).style.display = 'none';
            }}
          />
          <div>
            <h1 className="font-display font-bold text-3xl sm:text-4xl text-contrast">
              CVE Dashboard
            </h1>
            <p className="text-muted mt-1">
              Vulnerability scanning &amp; remediation at a glance
            </p>
          </div>
        </div>
        <div className="sm:ml-auto">
          <Button onClick={() => navigate('/repos')}>
            Scan New Repo
          </Button>
        </div>
      </div>

      {/* Loading / Error States */}
      {loading && (
        <div className="text-center py-16">
          <div className="inline-block w-8 h-8 border-4 border-border border-t-accent rounded-full animate-spin" />
          <p className="text-muted mt-4">Loading dashboard...</p>
        </div>
      )}

      {error && (
        <Card className="border-critical/40 mb-8">
          <p className="text-critical font-semibold">Error: {error}</p>
          <p className="text-muted text-sm mt-1">
            Make sure the git-steer API is running on port 4300.
          </p>
        </Card>
      )}

      {/* Stats Row */}
      {status && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
          <StatCard label="Total Repos" value={(status as any).repos?.managed ?? 0} />
          <StatCard label="Rate Limit" value={(status as any).github?.rateLimit?.core?.remaining ?? '—'} />
          <StatCard label="API Status" value={(status as any).github?.authenticated ? 'Connected' : 'Disconnected'} safe={(status as any).github?.authenticated} />
          <StatCard label="Version" value={(status as any).version ?? '—'} small />
        </div>
      )}

      {/* Recent Scan Queue */}
      <section>
        <div className="flex items-center justify-between mb-6">
          <h2 className="font-display font-bold text-xl text-contrast">Recent Scans</h2>
          <Link
            to="/repos"
            className="text-accent hover:text-contrast text-sm font-semibold uppercase tracking-wide transition-colors"
          >
            View all repos &rarr;
          </Link>
        </div>

        {queue.length === 0 && !loading && (
          <Card>
            <p className="text-muted text-center py-4">
              No recent scans. Add a repository to get started.
            </p>
          </Card>
        )}

        <div className="space-y-3">
          {queue.map((item, i) => (
            <Card
              key={`${item.owner}/${item.repo}-${i}`}
              onClick={() => navigate(`/repos/${item.owner}/${item.repo}`)}
              className="flex flex-col sm:flex-row sm:items-center gap-3"
            >
              <div className="flex-1 min-w-0">
                <p className="font-mono text-sm font-medium text-contrast truncate">
                  {item.owner}/{item.repo}
                </p>
                <p className="text-muted text-xs mt-0.5">
                  Queued {formatTime(item.queued_at)}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Badge severity={statusToSeverity(item.status)} />
                <span className="text-xs text-muted uppercase tracking-wide">
                  {item.status}
                </span>
              </div>
            </Card>
          ))}
        </div>
      </section>
    </div>
  );
}

// ---- Helpers ----

function StatCard({
  label,
  value,
  highlight,
  safe,
  small,
}: {
  label: string;
  value: string | number;
  highlight?: boolean;
  safe?: boolean;
  small?: boolean;
}) {
  return (
    <Card>
      <p className="text-muted text-xs uppercase tracking-wider font-semibold mb-1">{label}</p>
      <p
        className={`font-display font-bold ${small ? 'text-lg' : 'text-3xl'} ${
          highlight ? 'text-critical' : safe ? 'text-safe' : 'text-contrast'
        }`}
      >
        {value}
      </p>
    </Card>
  );
}

function formatTime(iso: string): string {
  if (!iso) return 'Never';
  try {
    const d = new Date(iso);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return iso;
  }
}

function statusToSeverity(status: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  switch (status.toLowerCase()) {
    case 'failed':
    case 'critical':
      return 'CRITICAL';
    case 'running':
    case 'pending':
      return 'MEDIUM';
    case 'complete':
    case 'done':
      return 'LOW';
    default:
      return 'HIGH';
  }
}
