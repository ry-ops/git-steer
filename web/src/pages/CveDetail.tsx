import { useParams, Link } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import SeverityIcon from '../components/SeverityIcon';

// Placeholder page -- will fetch from API once the CVE detail endpoint exists.
// For now, renders a static layout showing the intended structure.

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export default function CveDetail() {
  const { cveId } = useParams<{ cveId: string }>();

  // Placeholder data until a dedicated API endpoint is available
  const cve = {
    id: cveId ?? 'CVE-0000-00000',
    severity: 'HIGH' as Severity,
    package_name: 'example-package',
    installed_version: '1.2.3',
    fixed_version: '1.2.4',
    description:
      'This is a placeholder vulnerability description. Connect the git-steer API to see real data here.',
    nvd_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    affected_repos: ['git-fabric/sdk', 'git-fabric/k8s'],
  };

  return (
    <div className="animate-fade-in">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-muted mb-6">
        <Link to="/" className="hover:text-accent transition-colors">Dashboard</Link>
        <span>/</span>
        <span className="font-mono text-contrast">{cve.id}</span>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start gap-4 mb-8">
        <SeverityIcon severity={cve.severity} size={40} />
        <div className="flex-1">
          <h1 className="font-display font-bold text-3xl text-contrast">{cve.id}</h1>
          <div className="flex items-center gap-3 mt-2">
            <Badge severity={cve.severity} />
            <span className="text-muted text-sm font-mono">{cve.package_name}</span>
          </div>
        </div>
      </div>

      {/* Description */}
      <Card className="mb-6">
        <h2 className="font-display font-bold text-lg text-contrast mb-3">Description</h2>
        <p className="text-sm text-contrast leading-relaxed">{cve.description}</p>
      </Card>

      {/* Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {/* Package Info */}
        <Card>
          <h3 className="text-xs uppercase tracking-wider text-muted font-semibold mb-4">
            Package Details
          </h3>
          <dl className="space-y-3">
            <div>
              <dt className="text-xs text-muted uppercase tracking-wider">Package</dt>
              <dd className="font-mono text-sm text-contrast mt-0.5">{cve.package_name}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted uppercase tracking-wider">Installed Version</dt>
              <dd className="font-mono text-sm text-contrast mt-0.5">{cve.installed_version}</dd>
            </div>
            {cve.fixed_version && (
              <div>
                <dt className="text-xs text-muted uppercase tracking-wider">Fixed In</dt>
                <dd className="font-mono text-sm text-safe mt-0.5">{cve.fixed_version}</dd>
              </div>
            )}
          </dl>
        </Card>

        {/* References */}
        <Card>
          <h3 className="text-xs uppercase tracking-wider text-muted font-semibold mb-4">
            References
          </h3>
          <dl className="space-y-3">
            <div>
              <dt className="text-xs text-muted uppercase tracking-wider">NVD Entry</dt>
              <dd className="mt-0.5">
                <a
                  href={cve.nvd_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sm text-accent hover:text-contrast transition-colors"
                >
                  {cve.nvd_url}
                </a>
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted uppercase tracking-wider">Affected Repos</dt>
              <dd className="mt-1 flex flex-wrap gap-2">
                {cve.affected_repos.map((r) => (
                  <span
                    key={r}
                    className="inline-block px-3 py-1 bg-base rounded-full text-xs font-mono text-contrast border border-border"
                  >
                    {r}
                  </span>
                ))}
              </dd>
            </div>
          </dl>
        </Card>
      </div>

      {/* Fix Options */}
      <Card className="mb-6">
        <h2 className="font-display font-bold text-lg text-contrast mb-4">Fix Options</h2>
        {cve.fixed_version ? (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <div className="flex-1">
              <p className="text-sm text-contrast">
                Upgrade <span className="font-mono font-semibold">{cve.package_name}</span> from{' '}
                <span className="font-mono text-critical">{cve.installed_version}</span> to{' '}
                <span className="font-mono text-safe">{cve.fixed_version}</span>
              </p>
              <p className="text-xs text-muted mt-1">
                This will create a pull request with the version bump for each affected repository.
              </p>
            </div>
            <Button>Create Fix PR</Button>
          </div>
        ) : (
          <p className="text-muted text-sm">
            No fix version is available yet. Monitor this CVE for updates.
          </p>
        )}
      </Card>

      {/* TAEM Mission Status */}
      <Card>
        <h2 className="font-display font-bold text-lg text-contrast mb-3">TAEM Mission Status</h2>
        <div className="flex items-center gap-3 text-sm text-muted">
          <div className="w-3 h-3 rounded-full bg-border animate-pulse" />
          <p>No active TAEM mission for this CVE. Trigger a remediation to start one.</p>
        </div>
      </Card>
    </div>
  );
}
