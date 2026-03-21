import type { VexStatus } from '../lib/api';

interface VexBadgeProps {
  status: VexStatus;
  justification?: string;
}

const STATUS_STYLES: Record<VexStatus, { bg: string; text: string; border: string; label: string }> = {
  not_affected: {
    bg: 'bg-muted/15',
    text: 'text-muted',
    border: 'border-muted/40',
    label: 'Not Affected',
  },
  affected: {
    bg: 'bg-critical/15',
    text: 'text-critical',
    border: 'border-critical/40',
    label: 'Affected',
  },
  fixed: {
    bg: 'bg-safe/15',
    text: 'text-safe',
    border: 'border-safe/40',
    label: 'Fixed',
  },
  under_investigation: {
    bg: 'bg-warning/15',
    text: 'text-warning',
    border: 'border-warning/40',
    label: 'Investigating',
  },
};

export default function VexBadge({ status, justification }: VexBadgeProps) {
  const style = STATUS_STYLES[status];

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide border ${style.bg} ${style.text} ${style.border}`}
      title={justification ? `VEX: ${formatJustification(justification)}` : `VEX: ${style.label}`}
    >
      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
      {style.label}
    </span>
  );
}

function formatJustification(j: string): string {
  return j.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
