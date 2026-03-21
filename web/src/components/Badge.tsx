type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface BadgeProps {
  severity: Severity;
  count?: number;
}

const SEVERITY_CLASS: Record<Severity, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
};

export default function Badge({ severity, count }: BadgeProps) {
  return (
    <span className={`badge ${SEVERITY_CLASS[severity]}`}>
      <SeverityDot severity={severity} />
      {severity}
      {count !== undefined && <span className="ml-1 opacity-80">({count})</span>}
    </span>
  );
}

function SeverityDot({ severity }: { severity: Severity }) {
  const colors: Record<Severity, string> = {
    CRITICAL: 'bg-critical',
    HIGH: 'bg-warning',
    MEDIUM: 'bg-yellow-600',
    LOW: 'bg-safe',
  };

  return (
    <span className={`inline-block w-2 h-2 rounded-full ${colors[severity]}`} />
  );
}
