import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import SeverityIcon from '../components/SeverityIcon';
import { api } from '../lib/api';
import type { ScanResult, CveEntry } from '../lib/api';

export default function ScanResults() {
  const { owner, repo } = useParams<{ owner: string; repo: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [fixing, setFixing] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!owner || !repo) return;
    loadResults();
  }, [owner, repo]);

  async function loadResults() {
    if (!owner || !repo) return;
    try {
      const data = await api.cve.results(owner, repo);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scan results');
    } finally {
      setLoading(false);
    }
  }

  function toggleExpand(cveId: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(cveId)) next.delete(cveId);
      else next.add(cveId);
      return next;
    });
  }

  async function handleFix(cveId: string) {
    if (!owner || !repo) return;
    setFixing((prev) => new Set(prev).add(cveId));
    try {
      const res = await api.cve.fix(cveId, owner, repo);
      if (res.pr_url) {
        window.open(res.pr_url, '_blank');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fix failed');
    } finally {
      setFixing((prev) => {
        const next = new Set(prev);
        next.delete(cveId);
        return next;
      });
    }
  }

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sortedCves = result?.cves
    ? [...result.cves].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
    : [];

  return (
    <div className="animate-fade-in">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-muted mb-6">
        <Link to="/repos" className="hover:text-accent transition-colors">Repositories</Link>
        <span>/</span>
        <span className="font-mono text-contrast">{owner}/{repo}</span>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="font-display font-bold text-3xl text-contrast">
            Scan Results
          </h1>
          {result && (
            <p className="text-muted mt-1 text-sm">
              Scanned {new Date(result.scanned_at).toLocaleString()} &mdash;{' '}
              {result.cves.length} vulnerabilities found
            </p>
          )}
        </div>
        <Button
          onClick={() => {
            if (owner && repo) {
              api.cve.scan(owner, repo).then(() => loadResults());
            }
          }}
        >
          Rescan
        </Button>
      </div>

      {/* Loading / Error */}
      {loading && (
        <div className="text-center py-16">
          <div className="inline-block w-8 h-8 border-4 border-border border-t-accent rounded-full animate-spin" />
          <p className="text-muted mt-4">Loading scan results...</p>
        </div>
      )}

      {error && (
        <Card className="border-critical/40 mb-6">
          <p className="text-critical font-semibold text-sm">{error}</p>
        </Card>
      )}

      {/* Summary Counts */}
      {result && (
        <div className="flex flex-wrap gap-3 mb-8">
          <Badge severity="CRITICAL" count={result.counts.critical} />
          <Badge severity="HIGH" count={result.counts.high} />
          <Badge severity="MEDIUM" count={result.counts.medium} />
          <Badge severity="LOW" count={result.counts.low} />
        </div>
      )}

      {/* CVE List */}
      {sortedCves.length === 0 && !loading && result && (
        <Card>
          <div className="text-center py-8">
            <p className="text-safe font-display font-bold text-xl mb-1">All clear!</p>
            <p className="text-muted text-sm">No vulnerabilities found in this repository.</p>
          </div>
        </Card>
      )}

      <div className="space-y-3">
        {sortedCves.map((cve) => (
          <CveRow
            key={cve.id}
            cve={cve}
            isExpanded={expanded.has(cve.id)}
            isFixing={fixing.has(cve.id)}
            onToggle={() => toggleExpand(cve.id)}
            onFix={() => handleFix(cve.id)}
          />
        ))}
      </div>
    </div>
  );
}

function CveRow({
  cve,
  isExpanded,
  isFixing,
  onToggle,
  onFix,
}: {
  cve: CveEntry;
  isExpanded: boolean;
  isFixing: boolean;
  onToggle: () => void;
  onFix: () => void;
}) {
  return (
    <Card className={cve.dismissed ? 'opacity-50' : ''}>
      {/* Summary row */}
      <div
        className="flex flex-col sm:flex-row sm:items-center gap-3 cursor-pointer"
        onClick={onToggle}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter') onToggle(); }}
      >
        <SeverityIcon severity={cve.severity} size={24} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Link
              to={`/cve/${cve.id}`}
              onClick={(e) => e.stopPropagation()}
              className="font-mono text-sm font-semibold text-accent hover:text-contrast transition-colors"
            >
              {cve.id}
            </Link>
            <Badge severity={cve.severity} />
          </div>
          <p className="text-muted text-xs mt-0.5 truncate">
            {cve.package_name} {cve.installed_version}
            {cve.fixed_version && ` -> ${cve.fixed_version}`}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {cve.fixed_version && !cve.dismissed && (
            <Button
              variant="primary"
              className="text-xs py-2 px-4"
              onClick={(e) => {
                e.stopPropagation();
                onFix();
              }}
              disabled={isFixing}
            >
              {isFixing ? 'Creating PR...' : 'Fix'}
            </Button>
          )}
          <Button
            variant="secondary"
            className="text-xs py-2 px-4"
            onClick={(e) => {
              e.stopPropagation();
              // dismiss logic (placeholder)
            }}
          >
            Dismiss
          </Button>
        </div>

        {/* Expand chevron */}
        <svg
          className={`w-5 h-5 text-muted transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={2}
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
        </svg>
      </div>

      {/* Expanded detail */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t-2 border-dashed border-border">
          <p className="text-sm text-contrast leading-relaxed mb-3">{cve.description}</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-muted uppercase tracking-wider font-semibold">Package</span>
              <p className="font-mono text-contrast mt-0.5">{cve.package_name}</p>
            </div>
            <div>
              <span className="text-muted uppercase tracking-wider font-semibold">Installed</span>
              <p className="font-mono text-contrast mt-0.5">{cve.installed_version}</p>
            </div>
            {cve.fixed_version && (
              <div>
                <span className="text-muted uppercase tracking-wider font-semibold">Fix Available</span>
                <p className="font-mono text-safe mt-0.5">{cve.fixed_version}</p>
              </div>
            )}
            {cve.nvd_url && (
              <div>
                <span className="text-muted uppercase tracking-wider font-semibold">NVD Reference</span>
                <a
                  href={cve.nvd_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block font-mono text-accent hover:text-contrast text-xs mt-0.5 transition-colors"
                >
                  View on NVD &rarr;
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}
