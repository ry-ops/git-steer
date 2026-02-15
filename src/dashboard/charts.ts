/**
 * SVG Chart Functions
 *
 * Pure SVG chart generators for the analytics dashboard.
 * No external dependencies — outputs inline SVG strings.
 */

export interface BarChartData {
  labels: string[];
  values: number[];
  colors?: string[];
  title?: string;
}

export interface LineChartData {
  labels: string[];
  values: number[];
  secondaryValues?: number[];
  title?: string;
}

export interface TableData {
  headers: string[];
  rows: string[][];
  title?: string;
}

const DEFAULT_COLORS = ['#b60205', '#ff9800', '#fbca04', '#0e8a16', '#0075ca', '#6f42c1'];

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function svgBarChart(data: BarChartData): string {
  const width = 500;
  const height = 300;
  const padding = { top: 40, right: 20, bottom: 60, left: 50 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maxValue = Math.max(...data.values, 1);
  const barWidth = Math.min(60, (chartWidth / data.labels.length) * 0.7);
  const gap = (chartWidth - barWidth * data.labels.length) / (data.labels.length + 1);
  const colors = data.colors || DEFAULT_COLORS;

  const bars = data.labels.map((label, i) => {
    const barHeight = (data.values[i] / maxValue) * chartHeight;
    const x = padding.left + gap * (i + 1) + barWidth * i;
    const y = padding.top + chartHeight - barHeight;
    const color = colors[i % colors.length];

    return `
      <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" fill="${color}" rx="2"/>
      <text x="${x + barWidth / 2}" y="${y - 5}" text-anchor="middle" font-size="11" fill="#e0e0e0">${data.values[i]}</text>
      <text x="${x + barWidth / 2}" y="${height - padding.bottom + 15}" text-anchor="middle" font-size="10" fill="#999" transform="rotate(-30, ${x + barWidth / 2}, ${height - padding.bottom + 15})">${escapeXml(label)}</text>
    `;
  }).join('');

  // Y-axis ticks
  const tickCount = 5;
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) => {
    const val = Math.round((maxValue / tickCount) * i);
    const y = padding.top + chartHeight - (i / tickCount) * chartHeight;
    return `
      <line x1="${padding.left}" y1="${y}" x2="${padding.left + chartWidth}" y2="${y}" stroke="#333" stroke-dasharray="2"/>
      <text x="${padding.left - 5}" y="${y + 4}" text-anchor="end" font-size="10" fill="#999">${val}</text>
    `;
  }).join('');

  return `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    ${data.title ? `<text x="${width / 2}" y="20" text-anchor="middle" font-size="14" font-weight="bold" fill="#e0e0e0">${escapeXml(data.title)}</text>` : ''}
    ${ticks}
    ${bars}
  </svg>`;
}

export function svgLineChart(data: LineChartData): string {
  const width = 600;
  const height = 300;
  const padding = { top: 40, right: 80, bottom: 60, left: 50 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const allValues = [...data.values, ...(data.secondaryValues || [])];
  const maxValue = Math.max(...allValues, 1);
  const stepX = data.labels.length > 1 ? chartWidth / (data.labels.length - 1) : 0;

  function buildPath(values: number[]): string {
    return values.map((v, i) => {
      const x = padding.left + stepX * i;
      const y = padding.top + chartHeight - (v / maxValue) * chartHeight;
      return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
    }).join(' ');
  }

  const primaryPath = buildPath(data.values);
  const secondaryPath = data.secondaryValues ? buildPath(data.secondaryValues) : '';

  // Dots on primary line
  const dots = data.values.map((v, i) => {
    const x = padding.left + stepX * i;
    const y = padding.top + chartHeight - (v / maxValue) * chartHeight;
    return `<circle cx="${x}" cy="${y}" r="3" fill="#ff4444"/>`;
  }).join('');

  // X-axis labels (show every Nth label to avoid crowding)
  const labelInterval = Math.max(1, Math.floor(data.labels.length / 8));
  const xLabels = data.labels.map((label, i) => {
    if (i % labelInterval !== 0 && i !== data.labels.length - 1) return '';
    const x = padding.left + stepX * i;
    return `<text x="${x}" y="${height - padding.bottom + 15}" text-anchor="middle" font-size="9" fill="#999" transform="rotate(-45, ${x}, ${height - padding.bottom + 15})">${escapeXml(label)}</text>`;
  }).join('');

  // Y-axis ticks
  const tickCount = 5;
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) => {
    const val = Math.round((maxValue / tickCount) * i);
    const y = padding.top + chartHeight - (i / tickCount) * chartHeight;
    return `
      <line x1="${padding.left}" y1="${y}" x2="${padding.left + chartWidth}" y2="${y}" stroke="#333" stroke-dasharray="2"/>
      <text x="${padding.left - 5}" y="${y + 4}" text-anchor="end" font-size="10" fill="#999">${val}</text>
    `;
  }).join('');

  return `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    ${data.title ? `<text x="${width / 2}" y="20" text-anchor="middle" font-size="14" font-weight="bold" fill="#e0e0e0">${escapeXml(data.title)}</text>` : ''}
    ${ticks}
    <path d="${primaryPath}" fill="none" stroke="#ff4444" stroke-width="2"/>
    ${secondaryPath ? `<path d="${secondaryPath}" fill="none" stroke="#0e8a16" stroke-width="2" stroke-dasharray="4"/>` : ''}
    ${dots}
    ${xLabels}
    <!-- Legend -->
    <rect x="${width - 70}" y="${padding.top}" width="10" height="10" fill="#ff4444"/>
    <text x="${width - 55}" y="${padding.top + 9}" font-size="10" fill="#e0e0e0">Opened</text>
    ${data.secondaryValues ? `
    <rect x="${width - 70}" y="${padding.top + 18}" width="10" height="10" fill="#0e8a16"/>
    <text x="${width - 55}" y="${padding.top + 27}" font-size="10" fill="#e0e0e0">Fixed</text>
    ` : ''}
  </svg>`;
}

export function svgTable(data: TableData): string {
  const colWidth = 150;
  const rowHeight = 28;
  const headerHeight = 32;
  const width = colWidth * data.headers.length;
  const height = headerHeight + rowHeight * data.rows.length + (data.title ? 30 : 0);
  const titleOffset = data.title ? 30 : 0;

  const headerCells = data.headers.map((h, i) =>
    `<text x="${colWidth * i + colWidth / 2}" y="${titleOffset + 20}" text-anchor="middle" font-size="11" font-weight="bold" fill="#e0e0e0">${escapeXml(h)}</text>`
  ).join('');

  const headerBg = `<rect x="0" y="${titleOffset}" width="${width}" height="${headerHeight}" fill="#2a2a2a" rx="4"/>`;

  const rows = data.rows.map((row, ri) => {
    const y = titleOffset + headerHeight + rowHeight * ri;
    const bg = ri % 2 === 0 ? '#1e1e1e' : '#242424';
    const cells = row.map((cell, ci) =>
      `<text x="${colWidth * ci + colWidth / 2}" y="${y + 19}" text-anchor="middle" font-size="10" fill="#ccc">${escapeXml(cell)}</text>`
    ).join('');
    return `<rect x="0" y="${y}" width="${width}" height="${rowHeight}" fill="${bg}"/>${cells}`;
  }).join('');

  return `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    ${data.title ? `<text x="${width / 2}" y="20" text-anchor="middle" font-size="14" font-weight="bold" fill="#e0e0e0">${escapeXml(data.title)}</text>` : ''}
    ${headerBg}
    ${headerCells}
    ${rows}
  </svg>`;
}
