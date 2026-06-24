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
import { parse as parseYaml } from 'yaml';
import { generateDashboardHtml } from '../dist/dashboard/templates.js';

const token = process.env.GH_TOKEN;
if (!token || typeof token !== 'string' || !/^(ghp_|gho_|ghs_|ghu_|github_pat_)[a-zA-Z0-9_]+$/.test(token)) {
  console.error('GH_TOKEN environment variable is required and must be a valid GitHub token');
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
    // managed-repos.yaml is `repos: [{ owner, name, policies }]`. Parse it as
    // real YAML — the old `/^\s*-\s+(.+)$/` regex captured `owner: ry-ops` off
    // every entry, collapsing the whole fleet to one bogus name so the scan saw
    // zero alerts everywhere (falsely-clean dashboard). Mirrors the #77 fix to
    // heartbeat.yml. Also tolerates a legacy flat `- owner/name` list.
    const doc = parseYaml(content) || {};
    const entries = Array.isArray(doc) ? doc : (doc.repos || []);
    const repos = entries
      .map((r) => {
        if (typeof r === 'string') {
          const [owner, name] = r.split('/');
          return owner && name ? { owner, name, fullName: `${owner}/${name}` } : null;
        }
        if (r && r.owner && r.name) {
          return { owner: r.owner, name: r.name, fullName: `${r.owner}/${r.name}` };
        }
        return null;
      })
      .filter(Boolean);
    if (repos.length > 0) return repos;
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
    } catch (err) {
      process.stdout.write('x');
      console.error(`\n  Warning: ${repo.fullName}: ${err.message || 'scan failed'}`);
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

// ===== Load and persist timeline snapshots =====
async function loadTimeline() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/timeline.jsonl' }
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

async function saveTimeline(entries) {
  let sha;
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/timeline.jsonl' }
    );
    sha = data.sha;
  } catch {
    // File doesn't exist yet
  }
  const content = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner: STATE_OWNER,
    repo: STATE_REPO,
    path: 'state/timeline.jsonl',
    message: `Update timeline snapshot ${new Date().toISOString().split('T')[0]}`,
    content: Buffer.from(content).toString('base64'),
    sha,
    branch: 'main',
  });
}

// ===== Load CVE queue (fabric) =====
async function loadCveQueue() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/cve-queue.jsonl' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    return content
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch {
    return [];
  }
}

// ===== Load ADR-006 escalation state (state/cache.json `_escalation`) =====
async function loadEscalation() {
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'state/cache.json' }
    );
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    const cache = JSON.parse(content);
    return (cache && cache._escalation) || {};
  } catch {
    return {};
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
function buildMetrics(scanResults, rfcs, repos, timeline) {
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

  return {
    totalCves: totalCves + fixedCves,
    fixedCves,
    fixRate: (totalCves + fixedCves) > 0 ? fixedCves / (totalCves + fixedCves) : 0,
    avgMttr: mttrCount > 0 ? totalMttrHours / mttrCount : 0,
    bySeverity,
    byRepo,
    timeline,
  };
}

// ===== Classify a repo's ADR-006 escalation posture =====
function classifyEscalation(entry, threshold) {
  if (!entry) return { status: 'clear', consecutiveFallouts: 0, lastFloor: null, lastVerdict: null };
  const fallouts = entry.consecutive_fallouts || 0;
  let status;
  if (fallouts >= threshold) status = 'hard-stop';   // human-held: ladder exhausted N sweeps running
  else if (fallouts > 0) status = 'loop';            // still being auto-retried each sweep
  else status = 'clear';
  return {
    status,
    consecutiveFallouts: fallouts,
    lastFloor: entry.last_floor ?? null,
    lastVerdict: entry.last_verdict ?? null,
  };
}

// ===== Build the machine-readable fleet status artifact =====
// One small JSON so "what's the status of my repos?" is a single cheap fetch,
// not a live fleet rescan. Mirrors what the heartbeat already computed.
function buildStatus(scanResults, rfcs, repos, metrics, escalation, threshold) {
  const severityOrder = ['critical', 'high', 'medium', 'low'];

  // Union of managed repos and any repo carrying escalation state (so a
  // hard-stop is never hidden just because the repo dropped off the list).
  const repoNames = new Set(repos.map((r) => r.fullName));
  for (const k of Object.keys(escalation)) repoNames.add(k);

  const openBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const perRepo = [];

  for (const fullName of repoNames) {
    const alerts = scanResults[fullName] || [];
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) {
      if (bySeverity[a.severity] != null) {
        bySeverity[a.severity]++;
        openBySeverity[a.severity]++;
      }
    }
    const esc = classifyEscalation(escalation[fullName], threshold);
    perRepo.push({
      repo: fullName,
      openAlerts: alerts.length,
      bySeverity,
      fixed: metrics.byRepo[fullName]?.fixed || 0,
      escalation: esc.status,
      consecutiveFallouts: esc.consecutiveFallouts,
      lastFloor: esc.lastFloor,
      lastVerdict: esc.lastVerdict,
    });
  }

  // Surface worst-first: most open alerts, then severity weight.
  const sevWeight = (r) =>
    r.bySeverity.critical * 1000 + r.bySeverity.high * 100 + r.bySeverity.medium * 10 + r.bySeverity.low;
  perRepo.sort((a, b) => b.openAlerts - a.openAlerts || sevWeight(b) - sevWeight(a));

  const totalOpenAlerts = perRepo.reduce((s, r) => s + r.openAlerts, 0);

  return {
    generatedAt: new Date().toISOString(),
    dashboardUrl: `https://${STATE_OWNER}.github.io/${STATE_REPO}/`,
    fleet: {
      totalRepos: repos.length,
      reposWithOpenAlerts: perRepo.filter((r) => r.openAlerts > 0).length,
      totalOpenAlerts,
      openBySeverity,
      fixedCves: metrics.fixedCves,
      fixRate: metrics.fixRate,
      avgMttrHours: metrics.avgMttr,
    },
    escalation: {
      threshold,
      hardStop: perRepo.filter((r) => r.escalation === 'hard-stop').map((r) => r.repo),
      inLoop: perRepo.filter((r) => r.escalation === 'loop').map((r) => r.repo),
    },
    repos: perRepo,
  };
}

// ===== Deploy status.json to gh-pages (public, single unauthenticated fetch) =====
async function deployStatus(status) {
  let sha;
  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      { owner: STATE_OWNER, repo: STATE_REPO, path: 'status.json', ref: 'gh-pages' }
    );
    sha = data.sha;
  } catch {
    // File doesn't exist yet
  }

  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner: STATE_OWNER,
    repo: STATE_REPO,
    path: 'status.json',
    message: `Update fleet status ${status.generatedAt}`,
    content: Buffer.from(JSON.stringify(status, null, 2)).toString('base64'),
    sha,
    branch: 'gh-pages',
  });
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
  const timelineHistory = await loadTimeline();
  const cveQueue = await loadCveQueue();
  const escalation = await loadEscalation();
  console.log(`Loaded ${rfcs.length} RFCs, ${quality.length} quality entries, ${timelineHistory.length} timeline entries, ${cveQueue.length} CVE queue entries, ${Object.keys(escalation).length} escalation records\n`);

  console.log('Building metrics...');
  // Count current open/fixed for today's snapshot
  const todayStr = new Date().toISOString().split('T')[0];
  const openCount = Object.values(scanResults).flat().length;
  const fixedCount = rfcs.filter((r) => r.status === 'fixed' || r.status === 'closed')
    .reduce((s, r) => s + (r.vulnerabilities || []).length, 0);

  // Append today's entry (replace if already present for today)
  const timeline = timelineHistory.filter((e) => e.date !== todayStr);
  timeline.push({ date: todayStr, opened: openCount, fixed: fixedCount });
  timeline.sort((a, b) => a.date.localeCompare(b.date));

  await saveTimeline(timeline);

  const metrics = buildMetrics(scanResults, rfcs, repos, timeline);

  // Build + publish the machine-readable fleet status BEFORE the dashboard's
  // queue-merge mutates `metrics` below — keeps status.json based on actual
  // open Dependabot alerts + RFC fixes, the canonical "is my fleet clean" view.
  const ESCALATION_THRESHOLD = Number(process.env.ESCALATION_THRESHOLD) || 3;
  const status = buildStatus(scanResults, rfcs, repos, metrics, escalation, ESCALATION_THRESHOLD);
  console.log(
    `Fleet status: ${status.fleet.totalOpenAlerts} open alerts across ${status.fleet.reposWithOpenAlerts}/${status.fleet.totalRepos} repos ` +
    `(hard-stop: ${status.escalation.hardStop.length}, in-loop: ${status.escalation.inLoop.length})`
  );
  console.log('Publishing status.json to gh-pages...');
  await deployStatus(status);
  console.log(`Published https://${STATE_OWNER}.github.io/${STATE_REPO}/status.json\n`);

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

  // Merge fabric CVE queue entries into dashboard data
  if (cveQueue.length > 0) {
    // Group queue entries by repo
    const queueByRepo = {};
    for (const entry of cveQueue) {
      if (!queueByRepo[entry.repo]) queueByRepo[entry.repo] = [];
      queueByRepo[entry.repo].push(entry);
    }

    for (const [repo, entries] of Object.entries(queueByRepo)) {
      // Skip if already covered by an existing RFC for this repo
      if (dashRfcs.some((r) => r.repo === repo)) continue;

      const severityOrder = ['critical', 'high', 'medium', 'low'];
      const maxSev = entries.reduce((max, e) => {
        const s = (e.severity || 'low').toLowerCase();
        return severityOrder.indexOf(s) < severityOrder.indexOf(max) ? s : max;
      }, 'low');

      const prOpened = entries.some((e) => e.status === 'pr_opened');
      dashRfcs.push({
        repo,
        issueNumber: entries[0].prNumber || 0,
        issueUrl: entries[0].prUrl || '',
        severity: maxSev,
        status: prOpened ? 'in_progress' : 'open',
        ts: entries[0].detectedAt || new Date().toISOString(),
        vulnerabilities: entries.map((e) => ({
          cve: e.id || 'N/A',
          package: e.affectedPackage,
          severity: (e.severity || 'low').toLowerCase(),
          fixVersion: e.patchedVersion || null,
        })),
      });
    }

    // Update metrics with queue stats
    const queuePending = cveQueue.filter((e) => e.status === 'pending').length;
    const queueFixed = cveQueue.filter((e) => e.status === 'pr_opened').length;
    metrics.totalCves += cveQueue.length;
    metrics.fixedCves += queueFixed;
    metrics.fixRate = metrics.totalCves > 0 ? metrics.fixedCves / metrics.totalCves : 0;

    console.log(`Merged ${cveQueue.length} CVE queue entries (${queuePending} pending, ${queueFixed} with PRs)\n`);
  }

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
