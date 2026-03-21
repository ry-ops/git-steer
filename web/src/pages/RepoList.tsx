import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import { api } from '../lib/api';
import type { Repo } from '../lib/api';

export default function RepoList() {
  const navigate = useNavigate();
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Add repo form
  const [showForm, setShowForm] = useState(false);
  const [owner, setOwner] = useState('');
  const [repo, setRepo] = useState('');
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    loadRepos();
  }, []);

  async function loadRepos() {
    try {
      const data = await api.repos.list();
      setRepos(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load repos');
    } finally {
      setLoading(false);
    }
  }

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!owner.trim() || !repo.trim()) return;
    setAdding(true);
    try {
      await api.repos.add({ owner: owner.trim(), repo: repo.trim() });
      setOwner('');
      setRepo('');
      setShowForm(false);
      await loadRepos();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add repo');
    } finally {
      setAdding(false);
    }
  }

  async function handleScan(owner: string, repo: string) {
    try {
      await api.cve.scan(owner, repo);
      navigate(`/repos/${owner}/${repo}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
    }
  }

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="font-display font-bold text-3xl text-contrast">Repositories</h1>
          <p className="text-muted mt-1">Tracked repos and their vulnerability status</p>
        </div>
        <Button onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : 'Add Repo'}
        </Button>
      </div>

      {/* Add Repo Form */}
      {showForm && (
        <Card className="mb-8">
          <form onSubmit={handleAdd} className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <label htmlFor="owner" className="block text-xs uppercase tracking-wider text-muted font-semibold mb-1">
                Owner
              </label>
              <input
                id="owner"
                type="text"
                placeholder="e.g. git-fabric"
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                className="w-full px-4 py-2 rounded-lg border-2 border-border bg-base font-mono text-sm text-contrast placeholder:text-muted/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>
            <div className="flex-1">
              <label htmlFor="repo" className="block text-xs uppercase tracking-wider text-muted font-semibold mb-1">
                Repository
              </label>
              <input
                id="repo"
                type="text"
                placeholder="e.g. sdk"
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                className="w-full px-4 py-2 rounded-lg border-2 border-border bg-base font-mono text-sm text-contrast placeholder:text-muted/50 focus:outline-none focus:border-accent transition-colors"
              />
            </div>
            <div className="flex items-end">
              <Button type="submit" disabled={adding}>
                {adding ? 'Adding...' : 'Add'}
              </Button>
            </div>
          </form>
        </Card>
      )}

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
      {!loading && repos.length === 0 && (
        <Card>
          <p className="text-muted text-center py-8">
            No repositories tracked yet. Add one to get started.
          </p>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {repos.map((r) => (
          <Card
            key={`${r.owner}/${r.repo}`}
            onClick={() => navigate(`/repos/${r.owner}/${r.repo}`)}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="min-w-0 flex-1">
                <h3 className="font-mono text-sm font-semibold text-contrast truncate">
                  {r.owner}/{r.repo}
                </h3>
                <p className="text-muted text-xs mt-1">
                  {r.last_scan ? `Scanned ${formatRelative(r.last_scan)}` : 'Never scanned'}
                </p>
              </div>
            </div>

            {/* Severity Counts */}
            {r.cve_counts && (
              <div className="flex flex-wrap gap-2 mb-4">
                {r.cve_counts.critical > 0 && <Badge severity="CRITICAL" count={r.cve_counts.critical} />}
                {r.cve_counts.high > 0 && <Badge severity="HIGH" count={r.cve_counts.high} />}
                {r.cve_counts.medium > 0 && <Badge severity="MEDIUM" count={r.cve_counts.medium} />}
                {r.cve_counts.low > 0 && <Badge severity="LOW" count={r.cve_counts.low} />}
                {totalCves(r.cve_counts) === 0 && (
                  <span className="text-safe text-xs font-semibold uppercase tracking-wide">All clear</span>
                )}
              </div>
            )}

            <Button
              variant="secondary"
              className="w-full text-xs"
              onClick={(e) => {
                e.stopPropagation();
                handleScan(r.owner, r.repo);
              }}
            >
              Scan Now
            </Button>
          </Card>
        ))}
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

function totalCves(counts: { critical: number; high: number; medium: number; low: number }): number {
  return counts.critical + counts.high + counts.medium + counts.low;
}
