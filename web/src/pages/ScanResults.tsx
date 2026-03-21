import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import SeverityIcon from '../components/SeverityIcon';
import VexBadge from '../components/VexBadge';
import { api } from '../lib/api';
import type { ScanResult, CveEntry, FixAllResult, VexStatus, VexJustification, VexEntry } from '../lib/api';

type ScanPageStatus = 'idle' | 'scanning' | 'fixing' | 'verified';

export default function ScanResults() {
  const { owner, repo } = useParams<{ owner: string; repo: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [fixing, setFixing] = useState<Set<string>>(new Set());
  const [vexOpen, setVexOpen] = useState<Set<string>>(new Set());
  const [vexMap, setVexMap] = useState<Record<string, VexEntry>>({});

  // Fix All state
  const [pageStatus, setPageStatus] = useState<ScanPageStatus>('idle');
  const [fixAllProgress, setFixAllProgress] = useState<string | null>(null);
  const [fixAllResult, setFixAllResult] = useState<FixAllResult | null>(null);

  useEffect(() => {
    if (!owner || !repo) return;
    loadResults();
    loadVex();
  }, [owner, repo]);

  async function loadResults() {
    if (!owner || !repo) return;
    try {
      const data = await api.cve.results(owner, repo);
      // Transform API response to match UI expected shape
      const alerts = data?.alerts ?? [];
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      const cves = alerts.map((a: any) => {
        const sev = (a.severity ?? 'medium').toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        if (sev === 'CRITICAL') counts.critical++;
        else if (sev === 'HIGH') counts.high++;
        else if (sev === 'MEDIUM') counts.medium++;
        else counts.low++;
        return {
          id: a.cve ?? a.ghsaId ?? `ALERT-${a.alertNumber}`,
          severity: sev,
          package_name: a.package ?? 'unknown',
          installed_version: a.currentVersion ?? '',
          fixed_version: a.fixVersion ?? null,
          description: a.description ?? a.summary ?? '',
          nvd_url: a.cve ? `https://nvd.nist.gov/vuln/detail/${a.cve}` : null,
          url: a.url ?? null,
          dismissed: a.state === 'dismissed',
        };
      });
      setResult({
        repo: data.repo ?? `${owner}/${repo}`,
        scanned_at: new Date().toISOString(),
        cves,
        counts,
      } as any);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scan results');
    } finally {
      setLoading(false);
    }
  }

  async function loadVex() {
    if (!owner || !repo) return;
    try {
      const entries = await api.vex.list(owner, repo);
      const map: Record<string, VexEntry> = {};
      if (Array.isArray(entries)) {
        entries.forEach((e) => { map[e.cve_id] = e; });
      }
      setVexMap(map);
    } catch {
      // VEX not available yet, that's fine
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

  function toggleVex(cveId: string) {
    setVexOpen((prev) => {
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

  async function handleFixAll() {
    if (!owner || !repo) return;
    setPageStatus('fixing');
    setFixAllResult(null);
    setFixAllProgress('Starting fix-all...');
    try {
      const totalFixable = result?.cves.filter((c) => c.fixed_version && !c.dismissed).length ?? 0;
      setFixAllProgress(`Fixing 0 of ${totalFixable} vulnerabilities...`);
      const res = await api.cve.fixAll(owner, repo);
      setFixAllResult(res);
      setFixAllProgress(null);
      setPageStatus('idle');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fix all failed');
      setFixAllProgress(null);
      setPageStatus('idle');
    }
  }

  async function handleVerify() {
    if (!owner || !repo) return;
    setPageStatus('scanning');
    try {
      const res = await api.cve.verify(owner, repo);
      if (res.status === 'verified') {
        setPageStatus('verified');
      } else {
        setPageStatus('idle');
      }
      // Reload results to show the new scan
      await loadResults();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verify failed');
      setPageStatus('idle');
    }
  }

  async function handleVexSave(cveId: string, status: VexStatus, justification?: VexJustification, detail?: string) {
    if (!owner || !repo) return;
    try {
      const entry = await api.vex.set(owner, repo, { cve_id: cveId, status, justification, detail });
      setVexMap((prev) => ({ ...prev, [cveId]: entry }));
      setVexOpen((prev) => {
        const next = new Set(prev);
        next.delete(cveId);
        return next;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'VEX save failed');
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

      {/* Status Banner */}
      {pageStatus === 'scanning' && (
        <div className="flex items-center gap-3 mb-6 px-5 py-3 rounded-xl bg-warning/15 border-2 border-dashed border-warning/40">
          <div className="w-5 h-5 border-2 border-warning border-t-transparent rounded-full animate-spin flex-shrink-0" />
          <p className="text-sm font-semibold text-warning">Re-scanning to verify fixes...</p>
        </div>
      )}
      {pageStatus === 'fixing' && (
        <div className="flex items-center gap-3 mb-6 px-5 py-3 rounded-xl bg-accent/15 border-2 border-dashed border-accent/40">
          <div className="w-5 h-5 border-2 border-accent border-t-transparent rounded-full animate-spin flex-shrink-0" />
          <p className="text-sm font-semibold text-accent">{fixAllProgress ?? 'Applying fixes...'}</p>
        </div>
      )}
      {pageStatus === 'verified' && (
        <div className="flex items-center gap-3 mb-6 px-5 py-3 rounded-xl bg-safe/15 border-2 border-dashed border-safe/40">
          <svg className="w-5 h-5 text-safe flex-shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-sm font-semibold text-safe">All fixes verified</p>
        </div>
      )}

      {/* Fix All result summary */}
      {fixAllResult && (
        <div className="mb-6 px-5 py-3 rounded-xl bg-card border-2 border-dashed border-border">
          <p className="text-sm font-semibold text-contrast mb-1">Fix All Complete</p>
          <div className="flex flex-wrap gap-3 text-xs">
            <span className="text-safe font-semibold">{fixAllResult.fixed} fixed</span>
            <span className="text-muted font-semibold">{fixAllResult.no_fix} no fix available</span>
            {fixAllResult.failed > 0 && (
              <span className="text-critical font-semibold">{fixAllResult.failed} failed</span>
            )}
          </div>
        </div>
      )}

      {/* Header with actions */}
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
        <div className="flex items-center gap-3 flex-wrap">
          {/* Fix All button */}
          {result && result.cves.some((c) => c.fixed_version && !c.dismissed) && pageStatus !== 'fixing' && (
            <Button
              onClick={handleFixAll}
              className="text-xs"
            >
              Fix All
            </Button>
          )}
          {/* Verify button (shown after fixes) */}
          {fixAllResult && pageStatus !== 'scanning' && (
            <Button
              variant="secondary"
              onClick={handleVerify}
              className="text-xs"
            >
              Verify
            </Button>
          )}
          <Button
            variant="secondary"
            onClick={() => {
              if (owner && repo) {
                setPageStatus('scanning');
                api.cve.scan(owner, repo).then(() => {
                  loadResults();
                  setPageStatus('idle');
                });
              }
            }}
            className="text-xs"
          >
            Rescan
          </Button>
        </div>
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
            vex={vexMap[cve.id]}
            isExpanded={expanded.has(cve.id)}
            isFixing={fixing.has(cve.id)}
            isVexOpen={vexOpen.has(cve.id)}
            onToggle={() => toggleExpand(cve.id)}
            onFix={() => handleFix(cve.id)}
            onVexToggle={() => toggleVex(cve.id)}
            onVexSave={(status, justification, detail) => handleVexSave(cve.id, status, justification, detail)}
          />
        ))}
      </div>
    </div>
  );
}

function CveRow({
  cve,
  vex,
  isExpanded,
  isFixing,
  isVexOpen,
  onToggle,
  onFix,
  onVexToggle,
  onVexSave,
}: {
  cve: CveEntry;
  vex?: VexEntry;
  isExpanded: boolean;
  isFixing: boolean;
  isVexOpen: boolean;
  onToggle: () => void;
  onFix: () => void;
  onVexToggle: () => void;
  onVexSave: (status: VexStatus, justification?: VexJustification, detail?: string) => void;
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
            {vex && <VexBadge status={vex.status} justification={vex.justification} />}
          </div>
          <p className="text-muted text-xs mt-0.5 truncate">
            {cve.package_name} {cve.installed_version}
            {cve.fixed_version && ` -> ${cve.fixed_version}`}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
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
              onVexToggle();
            }}
          >
            VEX
          </Button>
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

      {/* VEX inline form */}
      {isVexOpen && (
        <VexForm
          existing={vex}
          onSave={onVexSave}
          onCancel={onVexToggle}
        />
      )}

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

const VEX_STATUSES: { value: VexStatus; label: string }[] = [
  { value: 'not_affected', label: 'Not Affected' },
  { value: 'affected', label: 'Affected' },
  { value: 'fixed', label: 'Fixed' },
  { value: 'under_investigation', label: 'Under Investigation' },
];

const VEX_JUSTIFICATIONS: { value: VexJustification; label: string }[] = [
  { value: 'component_not_present', label: 'Component not present' },
  { value: 'vulnerable_code_not_reachable', label: 'Vulnerable code not reachable' },
  { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'Cannot be controlled by adversary' },
  { value: 'vulnerable_code_not_in_execute_path', label: 'Not in execute path' },
  { value: 'inline_mitigations_already_exist', label: 'Inline mitigations exist' },
];

function VexForm({
  existing,
  onSave,
  onCancel,
}: {
  existing?: VexEntry;
  onSave: (status: VexStatus, justification?: VexJustification, detail?: string) => void;
  onCancel: () => void;
}) {
  const [status, setStatus] = useState<VexStatus>(existing?.status ?? 'not_affected');
  const [justification, setJustification] = useState<VexJustification | ''>(existing?.justification ?? '');
  const [detail, setDetail] = useState(existing?.detail ?? '');
  const [saving, setSaving] = useState(false);

  return (
    <div className="mt-4 pt-4 border-t-2 border-dashed border-border" onClick={(e) => e.stopPropagation()}>
      <p className="text-xs text-muted uppercase tracking-wider font-semibold mb-3">VEX Statement</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {/* Status */}
        <div>
          <label className="block text-xs text-muted font-semibold mb-1">Status</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as VexStatus)}
            className="w-full px-3 py-2 rounded-lg border-2 border-border bg-base text-sm text-contrast focus:outline-none focus:border-accent transition-colors"
          >
            {VEX_STATUSES.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>

        {/* Justification (shown when not_affected) */}
        {status === 'not_affected' && (
          <div>
            <label className="block text-xs text-muted font-semibold mb-1">Justification</label>
            <select
              value={justification}
              onChange={(e) => setJustification(e.target.value as VexJustification)}
              className="w-full px-3 py-2 rounded-lg border-2 border-border bg-base text-sm text-contrast focus:outline-none focus:border-accent transition-colors"
            >
              <option value="">Select justification...</option>
              {VEX_JUSTIFICATIONS.map((j) => (
                <option key={j.value} value={j.value}>{j.label}</option>
              ))}
            </select>
          </div>
        )}

        {/* Detail */}
        <div className={status === 'not_affected' ? 'sm:col-span-2' : ''}>
          <label className="block text-xs text-muted font-semibold mb-1">Detail (optional)</label>
          <input
            type="text"
            value={detail}
            onChange={(e) => setDetail(e.target.value)}
            placeholder="Additional context..."
            className="w-full px-3 py-2 rounded-lg border-2 border-border bg-base text-sm text-contrast placeholder:text-muted/50 focus:outline-none focus:border-accent transition-colors"
          />
        </div>
      </div>

      <div className="flex items-center gap-2 mt-3">
        <Button
          className="text-xs py-2 px-4"
          disabled={saving}
          onClick={() => {
            setSaving(true);
            onSave(status, justification || undefined, detail || undefined);
          }}
        >
          {saving ? 'Saving...' : 'Save VEX'}
        </Button>
        <Button
          variant="secondary"
          className="text-xs py-2 px-4"
          onClick={onCancel}
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}
