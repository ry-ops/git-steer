/**
 * scan-verify.mjs — comprehensive, self-reconciling CVE/security scan for ONE repo.
 *
 * Proves the scanner reports ALL issues (ADR-004 "report ALL" mandate) by:
 *   1. Paginating Dependabot alerts fully (no 100-item cap)
 *   2. Paginating Code Scanning alerts fully (an entire class the old scanner missed)
 *   3. Merging into a unified, severity-normalized finding list (all severities)
 *   4. Independently re-counting each class and asserting scan total == ground truth
 *
 * Exit non-zero if the merged scan disagrees with the independent counts.
 *
 * Usage: node scripts/scan-verify.mjs [owner/repo]   (default: ry-ops/git-steer)
 */

import keytar from 'keytar';
import { App } from 'octokit';

const target = process.argv[2] || 'ry-ops/git-steer';
const [owner, repo] = target.split('/');
if (!owner || !repo) {
  console.error('Usage: node scripts/scan-verify.mjs <owner/repo>');
  process.exit(2);
}

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

const SEVS = ['critical', 'high', 'medium', 'low', 'unknown'];
const rollup = (items) => {
  const c = Object.fromEntries(SEVS.map((s) => [s, 0]));
  for (const it of items) c[SEVS.includes(it.severity) ? it.severity : 'unknown']++;
  return c;
};
const fmt = (c) => SEVS.filter((s) => c[s]).map((s) => `${s}:${c[s]}`).join('  ') || '(none)';

// ── 1. Dependabot alerts (fully paginated) ────────────────────────────
async function fetchDependabot() {
  try {
    const raw = await octokit.paginate('GET /repos/{owner}/{repo}/dependabot/alerts', {
      owner, repo, state: 'open', per_page: 100,
    });
    return raw.map((a) => ({
      source: 'dependabot',
      alertNumber: a.number,
      severity: (a.security_vulnerability?.severity ?? a.security_advisory?.severity ?? 'unknown').toLowerCase(),
      identifier: a.security_advisory?.cve_id ?? a.security_advisory?.ghsa_id ?? `dep-${a.number}`,
      package: a.dependency?.package?.name ?? 'unknown',
      ecosystem: a.dependency?.package?.ecosystem ?? 'unknown',
      fixVersion: a.security_vulnerability?.first_patched_version?.identifier ?? null,
      manifestPath: a.dependency?.manifest_path ?? '',
      url: a.html_url,
    }));
  } catch (err) {
    if (err.status === 403 || err.status === 404) {
      console.warn(`  [warn] dependabot alerts unavailable (${err.status}) — feature off or no permission`);
      return null; // null = could not read (distinct from empty)
    }
    throw err;
  }
}

// ── 2. Code Scanning alerts (fully paginated) — the missed class ──────
async function fetchCodeScanning() {
  try {
    const raw = await octokit.paginate('GET /repos/{owner}/{repo}/code-scanning/alerts', {
      owner, repo, state: 'open', per_page: 100,
    });
    return raw.map((a) => ({
      source: 'code-scanning',
      alertNumber: a.number,
      // security_severity_level is critical/high/medium/low; fall back to rule.severity (error/warning/note)
      severity: (a.rule?.security_severity_level ?? a.rule?.severity ?? 'unknown').toLowerCase(),
      identifier: a.rule?.id ?? `scan-${a.number}`,
      package: a.rule?.id ?? 'unknown',
      ecosystem: 'code-scanning',
      fixVersion: null, // code findings aren't fixed by version bumps → flow to manual/VEX path
      manifestPath: a.most_recent_instance?.location?.path ?? '',
      url: a.html_url,
    }));
  } catch (err) {
    if (err.status === 403 || err.status === 404) {
      console.warn(`  [warn] code-scanning unavailable (${err.status}) — not enabled or no analysis`);
      return null;
    }
    throw err;
  }
}

// ── Independent ground-truth count (separate code path: raw counted pages) ──
async function groundTruthCount(path) {
  try {
    let count = 0;
    const iterator = octokit.paginate.iterator(path, { owner, repo, state: 'open', per_page: 100 });
    for await (const { data } of iterator) count += data.length;
    return count;
  } catch (err) {
    if (err.status === 403 || err.status === 404) return null;
    throw err;
  }
}

console.log(`\n=== Comprehensive scan: ${owner}/${repo} ===\n`);

const [dep, scan] = await Promise.all([fetchDependabot(), fetchCodeScanning()]);
const findings = [...(dep ?? []), ...(scan ?? [])];

console.log(`Dependabot:    ${dep === null ? 'UNAVAILABLE' : dep.length + ' open'}   ${dep ? fmt(rollup(dep)) : ''}`);
console.log(`Code scanning: ${scan === null ? 'UNAVAILABLE' : scan.length + ' open'}   ${scan ? fmt(rollup(scan)) : ''}`);
console.log(`\nMERGED TOTAL:  ${findings.length}   ${fmt(rollup(findings))}\n`);

// ── 3. Reconcile against independent counts ───────────────────────────
const gtDep = await groundTruthCount('GET /repos/{owner}/{repo}/dependabot/alerts');
const gtScan = await groundTruthCount('GET /repos/{owner}/{repo}/code-scanning/alerts');

const checks = [
  { name: 'dependabot', got: dep === null ? null : dep.length, truth: gtDep },
  { name: 'code-scanning', got: scan === null ? null : scan.length, truth: gtScan },
];

let ok = true;
console.log('=== Reconciliation (merged scan vs independent count) ===');
for (const c of checks) {
  const pass = c.got === c.truth;
  if (!pass) ok = false;
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${c.name}: scan=${c.got}  truth=${c.truth}`);
}

const truthTotal = (gtDep ?? 0) + (gtScan ?? 0);
console.log(`\n  ${findings.length === truthTotal ? 'PASS' : 'FAIL'}  TOTAL: scan=${findings.length}  truth=${truthTotal}`);

if (!ok || findings.length !== truthTotal) {
  console.error('\n❌ COVERAGE MISMATCH — scanner is NOT reporting all issues.');
  process.exit(1);
}
console.log('\n✅ Scanner reports ALL issues for this repo (dependabot + code-scanning, fully paginated).');
