/**
 * CI Dashboard Generator
 *
 * Runs in GitHub Actions (no local machine needed).
 * Uses a pre-generated installation token from actions/create-github-app-token.
 * Scans all repos for vulnerabilities, generates the dashboard HTML,
 * and deploys it to the git-steer-state gh-pages branch.
 *
 * Env vars:
 *   GH_TOKEN - GitHub installation token
 *   STATE_REPO - State repo name (default: git-steer-state)
 *   STATE_OWNER - State repo owner (default: ry-ops)
 */

import { Octokit } from 'octokit';
import { generateDashboardHtml } from '../dist/dashboard/templates.js';

const token = process.env.GH_TOKEN;
if (!token) {
  console.error('GH_TOKEN environment variable is required');
  process.exit(1);
}

const STATE_OWNER = process.env.STATE_OWNER || 'ry-ops';
const STATE_REPO = process.env.STATE_REPO || 'git-steer-state';

const octokit = new Octokit({ auth: token });

// ===== Fetch managed repos =====
async function getManagedRepos() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'config/managed-repos.yaml' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    const repos = content.match(/^\s*-\s+(.+)$/gm);
    if (repos) {
      return repos.map((r) => {
        const name = r.replace(/^\s*-\s+/, '').trim();
        const [owner, repo] = name.split('/');
        return { owner, name: repo, fullName: name };
      });
    }
  } catch {
    // fallback
  }

  // Fallback: list installation repos
  const { data } = await octokit.request('GET /installation/repositories');
  return data.repositories
    .filter((r) => !r.archived)
    .map((r) => ({ owner: r.owner.login, name: r.name, fullName: r.full_name }));
}

// ===== Scan repos for vulnerabilities =====
async function scanRepos(repos) {
  const results = {};
  const severityOrder = ['critical', 'high', 'medium', 'low'];

  for (const repo of repos) {
    try {
      const { data: alerts } = await octokit.request(
        'GET /repos/{owner}/{repo}/dependabot/alerts',
        { owner: repo.owner, repo: repo.name, state: 'open', per_page: 100 }
      );

      const detailed = alerts.map((a) => ({
        id: a.number,
        severity: a.security_advisory?.severity || 'low',
        package: a.dependency?.package?.name || 'unknown',
        cve: a.security_advisory?.cve_id || null,
        currentVersion: a.dependency?.package?.ecosystem || '',
        fixVersion: a.security_vulnerability?.first_patched_version?.identifier || null,
        manifestPath: a.dependency?.manifest_path || '',
        description: a.security_advisory?.summary || '',
        state: a.state,
      }));

      if (detailed.length > 0) {
        results[repo.fullName] = detailed;
        process.stdout.write('!');
      } else {
        process.stdout.write('.');
      }
    } catch {
      process.stdout.write('x');
    }
  }
  console.log('');
  return results;
}

// ===== Load existing RFCs from state repo =====
async function loadRfcs() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/rfcs.jsonl' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    return content
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

// ===== Load existing quality results =====
async function loadQuality() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/quality.jsonl' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    return content
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

// ===== Build metrics from scan results and RFCs =====
function buildMetrics(scanResults, rfcs, repos) {
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const bySeverity = {};
  const byRepo = {};

  for (const sev of severityOrder) {
    bySeverity[sev] = { total: 0, fixed: 0 };
  }

  // Count from scan results (current open alerts)
  for (const [repoName, alerts] of Object.entries(scanResults)) {
    byRepo[repoName] = { total: alerts.length, fixed: 0 };
    for (const a of alerts) {
      if (bySeverity[a.severity]) {
        bySeverity[a.severity].total++;
      }
    }
  }

  // Add repos with no alerts
  for (const repo of repos) {
    if (!byRepo[repo.fullName]) {
      byRepo[repo.fullName] = { total: 0, fixed: 0 };
    }
  }

  // Count fixed from RFCs
  let fixedCves = 0;
  for (const rfc of rfcs) {
    if (rfc.status === 'fixed' || rfc.status === 'closed') {
      fixedCves += (rfc.vulnerabilities || []).length;
      if (byRepo[rfc.repo]) {
        byRepo[rfc.repo].fixed += (rfc.vulnerabilities || []).length;
      }
    }
  }

  const totalCves = Object.values(bySeverity).reduce((s, v) => s + v.total, 0);

  // Calculate MTTR from fixed RFCs
  let totalMttrHours = 0;
  let mttrCount = 0;
  for (const rfc of rfcs) {
    if ((rfc.status === 'fixed' || rfc.status === 'closed') && rfc.ts && rfc.fixedAt) {
      const hours = (new Date(rfc.fixedAt) - new Date(rfc.ts)) / 3600000;
      totalMttrHours += hours;
      mttrCount++;
    }
  }

  const today = new Date().toISOString().split('T')[0];

  return {
    totalCves: totalCves + fixedCves,
    fixedCves,
    fixRate: (totalCves + fixedCves) > 0 ? fixedCves / (totalCves + fixedCves) : 0,
    avgMttr: mttrCount > 0 ? totalMttrHours / mttrCount : 0,
    bySeverity,
    byRepo,
    timeline: [{ date: today, opened: totalCves, fixed: fixedCves }],
  };
}

// ===== Deploy dashboard to gh-pages =====
async function deployDashboard(html) {
  // Get current file SHA
  let sha;
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'index.html', ref: 'gh-pages' }
    );
    sha = data.sha;
  } catch {
    // File doesn't exist yet
  }

  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner: STATE_OWNER,
    repo: STATE_REPO,
    path: 'index.html',
    message: `Update dashboard ${new Date().toISOString()}`,
    content: Buffer.from(html).toString('base64'),
    sha,
    branch: 'gh-pages',
  });
}

// ===== Main =====
async function main() {
  console.log('=== git-steer CI Dashboard Generator ===\n');

  console.log('Fetching managed repos...');
  const repos = await getManagedRepos();
  console.log(`Found ${repos.length} repos\n`);

  console.log('Scanning for vulnerabilities...');
  const scanResults = await scanRepos(repos);
  const totalAlerts = Object.values(scanResults).flat().length;
  const reposWithAlerts = Object.keys(scanResults).length;
  console.log(`Found ${totalAlerts} alerts across ${reposWithAlerts} repos\n`);

  console.log('Loading state data...');
  const rfcs = await loadRfcs();
  const quality = await loadQuality();
  console.log(`Loaded ${rfcs.length} RFCs, ${quality.length} quality entries\n`);

  console.log('Building metrics...');
  const metrics = buildMetrics(scanResults, rfcs, repos);

  // Convert scan results to RFC-like format for the dashboard
  const dashRfcs = rfcs.length > 0 ? rfcs : Object.entries(scanResults).map(([repo, alerts]) => ({
    repo,
    issueNumber: 0,
    issueUrl: '',
    severity: alerts.reduce((max, a) => {
      const order = ['critical', 'high', 'medium', 'low'];
      return order.indexOf(a.severity) < order.indexOf(max) ? a.severity : max;
    }, 'low'),
    status: 'open',
    ts: new Date().toISOString(),
    vulnerabilities: alerts.map((a) => ({
      cve: a.cve,
      package: a.package,
      severity: a.severity,
      fixVersion: a.fixVersion,
    })),
  }));

  console.log('Generating dashboard HTML...');
  const html = generateDashboardHtml({
    metrics,
    rfcs: dashRfcs,
    quality,
  });
  console.log(`Dashboard size: ${html.length} bytes\n`);

  console.log('Deploying to GitHub Pages...');
  await deployDashboard(html);
  console.log(`Deployed to https://${STATE_OWNER}.github.io/${STATE_REPO}/\n`);

  console.log('Done!');
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
