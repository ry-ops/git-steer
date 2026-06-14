/**
 * Remediate all fixable security alerts by directly updating dependency files
 * via the GitHub Contents API + creating PRs. No local checkout needed.
 *
 * Strategy:
 * - npm: bump versions in package.json (direct deps) to fix version
 * - pip: bump versions in requirements*.txt to >= fix version
 * - Creates one PR per repo with all fixes
 */

import keytar from 'keytar';
import { App } from 'octokit';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// --- Step 1: Get all repos with fixable alerts ---
const { data } = await octokit.request('GET /installation/repositories');
const repos = data.repositories.filter(r => !r.archived);

console.log(`Scanning ${repos.length} repos for fixable alerts...\n`);

const repoAlerts = {};

for (const repo of repos) {
  try {
    // Fully paginated — do not truncate repos with >100 alerts.
    const alerts = await octokit.paginate(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      { owner: repo.owner.login, repo: repo.name, state: 'open', per_page: 100 }
    );
    const fixable = alerts.filter(a => a.security_vulnerability?.first_patched_version?.identifier);
    if (fixable.length > 0) {
      repoAlerts[`${repo.owner.login}/${repo.name}`] = fixable.map(a => ({
        package: a.dependency?.package?.name,
        ecosystem: a.dependency?.package?.ecosystem,
        manifest: a.dependency?.manifest_path,
        severity: a.security_advisory?.severity,
        cve: a.security_advisory?.cve_id || a.security_advisory?.ghsa_id,
        fixVersion: a.security_vulnerability.first_patched_version.identifier,
        scope: a.dependency?.scope,
      }));
    }
    process.stdout.write('.');
  } catch {
    process.stdout.write('x');
  }
}

console.log('\n');

const totalFixable = Object.values(repoAlerts).flat().length;
console.log(`Found ${totalFixable} fixable alerts across ${Object.keys(repoAlerts).length} repos.\n`);

// --- Step 2: Remediate each repo in parallel ---

async function remediateRepo(fullName, alerts) {
  const [owner, repo] = fullName.split('/');
  const branchName = `security/remediate-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;

  try {
    // Get default branch ref
    const { data: repoData } = await octokit.request('GET /repos/{owner}/{repo}', { owner, repo });
    const defaultBranch = repoData.default_branch;

    const { data: refData } = await octokit.request('GET /repos/{owner}/{repo}/git/ref/{ref}', {
      owner, repo, ref: `heads/${defaultBranch}`,
    });
    const baseSha = refData.object.sha;

    // Group alerts by manifest file
    const byManifest = {};
    for (const alert of alerts) {
      const manifest = alert.manifest || (alert.ecosystem === 'pip' ? 'requirements.txt' : 'package.json');
      if (!byManifest[manifest]) byManifest[manifest] = [];
      byManifest[manifest].push(alert);
    }

    // Read and update each manifest
    const fileUpdates = [];

    for (const [manifestPath, manifestAlerts] of Object.entries(byManifest)) {
      try {
        const { data: fileData } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
          owner, repo, path: manifestPath, ref: defaultBranch,
        });

        let content = Buffer.from(fileData.content, 'base64').toString('utf-8');
        let modified = false;
        const ecosystem = manifestAlerts[0].ecosystem;

        if (ecosystem === 'npm') {
          // Parse package.json and bump versions
          const pkg = JSON.parse(content);
          const sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

          for (const alert of manifestAlerts) {
            for (const section of sections) {
              if (pkg[section] && pkg[section][alert.package]) {
                const currentRange = pkg[section][alert.package];
                // Only bump if it's a semver range we can safely update
                if (!currentRange.startsWith('http') && !currentRange.startsWith('git')) {
                  pkg[section][alert.package] = `^${alert.fixVersion}`;
                  modified = true;
                }
              }
            }
          }

          if (modified) {
            content = JSON.stringify(pkg, null, 2) + '\n';
          }
        } else if (ecosystem === 'pip') {
          // Update requirements files
          for (const alert of manifestAlerts) {
            const pkgName = alert.package;
            const fixVer = alert.fixVersion;
            // Match various pip version specifier patterns
            const patterns = [
              new RegExp(`^(${pkgName})([=<>!~]=?.*)$`, 'mi'),
              new RegExp(`^(${pkgName})\\s*$`, 'mi'),
            ];

            let matched = false;
            for (const pattern of patterns) {
              if (pattern.test(content)) {
                content = content.replace(pattern, `${pkgName}>=${fixVer}`);
                modified = true;
                matched = true;
                break;
              }
            }

            // If not found in requirements, might be in pyproject.toml dep list
            if (!matched && manifestPath.endsWith('pyproject.toml')) {
              const depPattern = new RegExp(`"${pkgName}[^"]*"`, 'gi');
              if (depPattern.test(content)) {
                content = content.replace(depPattern, `"${pkgName}>=${fixVer}"`);
                modified = true;
              }
            }
          }
        }

        if (modified) {
          fileUpdates.push({
            path: manifestPath,
            content,
            sha: fileData.sha,
          });
        }
      } catch (e) {
        // File not found or other error — skip
      }
    }

    if (fileUpdates.length === 0) {
      return { repo: fullName, status: 'skipped', reason: 'no manifest changes needed (transitive deps only)' };
    }

    // Create branch
    await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
      owner, repo,
      ref: `refs/heads/${branchName}`,
      sha: baseSha,
    });

    // Commit each file update
    for (const file of fileUpdates) {
      await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
        owner, repo,
        path: file.path,
        message: `fix(security): bump versions in ${file.path}`,
        content: Buffer.from(file.content).toString('base64'),
        sha: file.sha,
        branch: branchName,
      });
    }

    // Build PR body
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) bySev[a.severity] = (bySev[a.severity] || 0) + 1;

    const rows = alerts.map(a => `| ${a.cve || 'N/A'} | ${a.package} | ${a.severity.toUpperCase()} | ${a.fixVersion} |`).join('\n');

    const body = `## Security Remediation

This PR addresses **${alerts.length}** security vulnerabilities by bumping dependency versions.

### Vulnerabilities Fixed

| CVE | Package | Severity | Fix Version |
|-----|---------|----------|-------------|
${rows}

### Summary
- Critical: ${bySev.critical}  High: ${bySev.high}  Medium: ${bySev.medium}  Low: ${bySev.low}

### Files Modified
${fileUpdates.map(f => `- \`${f.path}\``).join('\n')}

> **Note:** Lock files will need to be regenerated. Run \`npm install\` or \`pip install -r requirements.txt\` after merge.

---
Generated by [git-steer](https://github.com/ry-ops/git-steer) automated remediation`;

    // Create PR
    const { data: pr } = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
      owner, repo,
      title: `fix(security): patch ${alerts.length} vulnerabilities`,
      body,
      head: branchName,
      base: defaultBranch,
    });

    // Add labels (best effort)
    try {
      await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
        owner, repo, issue_number: pr.number,
        labels: ['security', 'dependencies', 'automated'],
      });
    } catch {}

    return { repo: fullName, status: 'pr_created', prUrl: pr.html_url, prNumber: pr.number, fixes: alerts.length, filesChanged: fileUpdates.length };
  } catch (e) {
    return { repo: fullName, status: 'error', error: e.message };
  }
}

// Execute all in parallel
console.log('Remediating all repos in parallel...\n');

const results = await Promise.allSettled(
  Object.entries(repoAlerts).map(([repo, alerts]) => remediateRepo(repo, alerts))
);

// --- Step 3: Report results ---
console.log('=== REMEDIATION RESULTS ===\n');

let prsCreated = 0;
let skipped = 0;
let errors = 0;
let totalFixed = 0;

for (const result of results) {
  const r = result.status === 'fulfilled' ? result.value : { repo: 'unknown', status: 'error', error: result.reason?.message };

  if (r.status === 'pr_created') {
    console.log(`  [PR] ${r.repo}: ${r.fixes} fixes → ${r.prUrl}`);
    prsCreated++;
    totalFixed += r.fixes;
  } else if (r.status === 'skipped') {
    console.log(`  [SKIP] ${r.repo}: ${r.reason}`);
    skipped++;
  } else {
    console.log(`  [ERR] ${r.repo}: ${r.error}`);
    errors++;
  }
}

console.log(`\n=== SUMMARY ===`);
console.log(`PRs created:    ${prsCreated}`);
console.log(`Fixes included: ${totalFixed}`);
console.log(`Skipped:        ${skipped}`);
console.log(`Errors:         ${errors}`);
