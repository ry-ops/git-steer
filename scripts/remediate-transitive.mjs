/**
 * Remediate transitive dependency vulnerabilities by deleting lock files
 * and letting the ecosystem regenerate them with patched versions.
 *
 * For repos where direct dep bumps weren't enough:
 * - npm: delete package-lock.json (forces fresh resolution)
 * - pip/uv: delete uv.lock or update constraint files
 */

import keytar from 'keytar';
import { App } from 'octokit';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// Repos that need transitive dep fixes
const targetRepos = [
  'ry-ops/unifi-cloudflare-ddns',
  'ry-ops/aiana',
  'ry-ops/ATSFlow',
  'ry-ops/qdrant-fabric',
  'ry-ops/homelab-hub-plus',
];

async function remediateTransitive(fullName) {
  const [owner, repo] = fullName.split('/');
  const branchName = `security/update-locks-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;

  try {
    // Get alerts for context
    const { data: alerts } = await octokit.request(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      { owner, repo, state: 'open', per_page: 100 }
    );
    const fixable = alerts.filter(a => a.security_vulnerability?.first_patched_version?.identifier);
    if (fixable.length === 0) return { repo: fullName, status: 'clean', fixes: 0 };

    // Detect ecosystem
    const ecosystems = [...new Set(fixable.map(a => a.dependency?.package?.ecosystem))];

    // Get default branch
    const { data: repoData } = await octokit.request('GET /repos/{owner}/{repo}', { owner, repo });
    const defaultBranch = repoData.default_branch;
    const { data: refData } = await octokit.request('GET /repos/{owner}/{repo}/git/ref/{ref}', {
      owner, repo, ref: `heads/${defaultBranch}`,
    });
    const baseSha = refData.object.sha;

    // Find lock files to delete
    const lockFileCandidates = [];
    if (ecosystems.includes('npm')) {
      lockFileCandidates.push('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml');
    }
    if (ecosystems.includes('pip')) {
      lockFileCandidates.push('uv.lock', 'poetry.lock', 'requirements.lock');
    }

    // Also look for lock files in subdirectories based on manifest paths
    const manifestPaths = [...new Set(fixable.map(a => a.dependency?.manifest_path).filter(Boolean))];
    for (const mp of manifestPaths) {
      const dir = mp.includes('/') ? mp.substring(0, mp.lastIndexOf('/')) : '';
      if (dir) {
        if (ecosystems.includes('npm')) {
          lockFileCandidates.push(`${dir}/package-lock.json`, `${dir}/yarn.lock`);
        }
        if (ecosystems.includes('pip')) {
          lockFileCandidates.push(`${dir}/uv.lock`, `${dir}/poetry.lock`);
        }
      }
    }

    // Check which lock files exist
    const existingLocks = [];
    for (const lockFile of [...new Set(lockFileCandidates)]) {
      try {
        const { data: f } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
          owner, repo, path: lockFile, ref: defaultBranch,
        });
        existingLocks.push({ path: lockFile, sha: f.sha });
      } catch {
        // doesn't exist
      }
    }

    if (existingLocks.length === 0) {
      // No lock files found — try bumping parent packages in package.json instead
      // For npm transitive deps, we need to add resolutions/overrides
      return await addOverrides(owner, repo, defaultBranch, baseSha, fixable, branchName);
    }

    // Create branch
    await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
      owner, repo,
      ref: `refs/heads/${branchName}`,
      sha: baseSha,
    });

    // Delete lock files (forces regeneration on next install)
    for (const lock of existingLocks) {
      await octokit.request('DELETE /repos/{owner}/{repo}/contents/{path}', {
        owner, repo,
        path: lock.path,
        message: `fix(security): remove ${lock.path} to force dependency resolution`,
        sha: lock.sha,
        branch: branchName,
      });
    }

    // Create PR
    const bySev = {};
    for (const a of fixable) {
      const s = a.security_advisory?.severity || 'unknown';
      bySev[s] = (bySev[s] || 0) + 1;
    }

    const pkgList = [...new Set(fixable.map(a => a.dependency?.package?.name))].join(', ');

    const body = `## Security: Force Dependency Resolution

This PR removes lock files to force fresh dependency resolution, picking up patched versions of transitive dependencies.

### Affected Packages
${[...new Set(fixable.map(a => `- \`${a.dependency?.package?.name}\` (${a.security_advisory?.severity}) → fix: ${a.security_vulnerability?.first_patched_version?.identifier}`))].join('\n')}

### Lock Files Removed
${existingLocks.map(l => `- \`${l.path}\``).join('\n')}

### Summary
- Vulnerabilities addressed: ${fixable.length}
- Critical: ${bySev.critical || 0}  High: ${bySev.high || 0}  Medium: ${bySev.medium || 0}  Low: ${bySev.low || 0}

### After Merge
Run \`npm install\` / \`uv sync\` / \`pip install -r requirements.txt\` to regenerate lock files.

---
Generated by [git-steer](https://github.com/ry-ops/git-steer) automated remediation`;

    const { data: pr } = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
      owner, repo,
      title: `fix(security): update transitive deps (${fixable.length} vulns)`,
      body,
      head: branchName,
      base: defaultBranch,
    });

    try {
      await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
        owner, repo, issue_number: pr.number,
        labels: ['security', 'dependencies', 'automated'],
      });
    } catch {}

    return { repo: fullName, status: 'pr_created', prUrl: pr.html_url, fixes: fixable.length, locksRemoved: existingLocks.length };
  } catch (e) {
    return { repo: fullName, status: 'error', error: e.message };
  }
}

async function addOverrides(owner, repo, defaultBranch, baseSha, fixable, branchName) {
  const fullName = `${owner}/${repo}`;
  const ecosystems = [...new Set(fixable.map(a => a.dependency?.package?.ecosystem))];

  // For npm — add overrides to package.json
  if (ecosystems.includes('npm')) {
    try {
      // Find all package.json files from manifests
      const manifests = [...new Set(fixable.filter(a => a.dependency?.package?.ecosystem === 'npm').map(a => a.dependency?.manifest_path || 'package.json'))];

      const fileUpdates = [];
      for (const manifestPath of manifests) {
        try {
          const { data: fileData } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner, repo, path: manifestPath, ref: defaultBranch,
          });

          let content = Buffer.from(fileData.content, 'base64').toString('utf-8');
          const pkg = JSON.parse(content);

          // Add npm overrides for transitive deps
          if (!pkg.overrides) pkg.overrides = {};

          const npmAlerts = fixable.filter(a => a.dependency?.package?.ecosystem === 'npm');
          for (const alert of npmAlerts) {
            const pkgName = alert.dependency?.package?.name;
            const fixVer = alert.security_vulnerability?.first_patched_version?.identifier;
            if (pkgName && fixVer) {
              pkg.overrides[pkgName] = `>=${fixVer}`;
            }
          }

          content = JSON.stringify(pkg, null, 2) + '\n';
          fileUpdates.push({ path: manifestPath, content, sha: fileData.sha });
        } catch {}
      }

      if (fileUpdates.length > 0) {
        await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
          owner, repo,
          ref: `refs/heads/${branchName}`,
          sha: baseSha,
        });

        for (const file of fileUpdates) {
          await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
            owner, repo,
            path: file.path,
            message: `fix(security): add npm overrides for transitive deps`,
            content: Buffer.from(file.content).toString('base64'),
            sha: file.sha,
            branch: branchName,
          });
        }

        const npmAlerts = fixable.filter(a => a.dependency?.package?.ecosystem === 'npm');
        const body = `## Security: Add npm overrides for transitive dependencies

This PR adds \`overrides\` to package.json to force resolution of patched transitive dependency versions.

### Packages Overridden
${[...new Set(npmAlerts.map(a => `- \`${a.dependency?.package?.name}\` >= ${a.security_vulnerability?.first_patched_version?.identifier}`))].join('\n')}

### After Merge
Run \`npm install\` to apply the overrides and regenerate the lock file.

---
Generated by [git-steer](https://github.com/ry-ops/git-steer) automated remediation`;

        const { data: pr } = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
          owner, repo,
          title: `fix(security): override ${npmAlerts.length} transitive deps`,
          body,
          head: branchName,
          base: defaultBranch,
        });

        try {
          await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
            owner, repo, issue_number: pr.number,
            labels: ['security', 'dependencies', 'automated'],
          });
        } catch {}

        return { repo: fullName, status: 'pr_created', prUrl: pr.html_url, fixes: npmAlerts.length, method: 'overrides' };
      }
    } catch {}
  }

  // For pip — add constraints or bump in pyproject.toml
  if (ecosystems.includes('pip')) {
    try {
      const pipAlerts = fixable.filter(a => a.dependency?.package?.ecosystem === 'pip');
      const manifests = [...new Set(pipAlerts.map(a => a.dependency?.manifest_path || 'requirements.txt'))];

      const fileUpdates = [];
      for (const manifestPath of manifests) {
        try {
          const { data: fileData } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner, repo, path: manifestPath, ref: defaultBranch,
          });

          let content = Buffer.from(fileData.content, 'base64').toString('utf-8');
          let modified = false;

          if (manifestPath.endsWith('.toml')) {
            // pyproject.toml — try to add constraints
            for (const alert of pipAlerts) {
              const pkgName = alert.dependency?.package?.name;
              const fixVer = alert.security_vulnerability?.first_patched_version?.identifier;
              // Try to find and update existing dep
              const pattern = new RegExp(`"${pkgName}([^"]*)"`, 'gi');
              if (pattern.test(content)) {
                content = content.replace(pattern, `"${pkgName}>=${fixVer}"`);
                modified = true;
              }
            }
          } else {
            // requirements.txt — add constraints for missing packages
            for (const alert of pipAlerts) {
              const pkgName = alert.dependency?.package?.name;
              const fixVer = alert.security_vulnerability?.first_patched_version?.identifier;
              const pattern = new RegExp(`^${pkgName}[=<>!~].*$`, 'mi');
              if (pattern.test(content)) {
                content = content.replace(pattern, `${pkgName}>=${fixVer}`);
                modified = true;
              } else {
                // Add as new constraint
                content += `${pkgName}>=${fixVer}\n`;
                modified = true;
              }
            }
          }

          if (modified) {
            fileUpdates.push({ path: manifestPath, content, sha: fileData.sha });
          }
        } catch {}
      }

      if (fileUpdates.length > 0) {
        await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
          owner, repo,
          ref: `refs/heads/${branchName}`,
          sha: baseSha,
        });

        for (const file of fileUpdates) {
          await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
            owner, repo,
            path: file.path,
            message: `fix(security): pin transitive pip deps to patched versions`,
            content: Buffer.from(file.content).toString('base64'),
            sha: file.sha,
            branch: branchName,
          });
        }

        const body = `## Security: Pin transitive pip dependencies

This PR adds version constraints for transitive dependencies with known vulnerabilities.

### Packages Pinned
${[...new Set(pipAlerts.map(a => `- \`${a.dependency?.package?.name}\` >= ${a.security_vulnerability?.first_patched_version?.identifier}`))].join('\n')}

### After Merge
Run \`pip install -r requirements.txt\` or \`uv sync\` to apply constraints.

---
Generated by [git-steer](https://github.com/ry-ops/git-steer) automated remediation`;

        const { data: pr } = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
          owner, repo,
          title: `fix(security): pin ${pipAlerts.length} transitive deps`,
          body,
          head: branchName,
          base: defaultBranch,
        });

        try {
          await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
            owner, repo, issue_number: pr.number,
            labels: ['security', 'dependencies', 'automated'],
          });
        } catch {}

        return { repo: fullName, status: 'pr_created', prUrl: pr.html_url, fixes: pipAlerts.length, method: 'constraints' };
      }
    } catch {}
  }

  return { repo: fullName, status: 'skipped', reason: 'could not determine remediation strategy' };
}

// --- Execute ---
console.log(`Remediating ${targetRepos.length} repos with transitive dep issues...\n`);

const results = await Promise.allSettled(
  targetRepos.map(repo => remediateTransitive(repo))
);

console.log('=== TRANSITIVE DEP REMEDIATION RESULTS ===\n');

let prs = 0;
let totalFixes = 0;

for (const result of results) {
  const r = result.status === 'fulfilled' ? result.value : { repo: 'unknown', status: 'error', error: result.reason?.message };

  if (r.status === 'pr_created') {
    console.log(`  [PR] ${r.repo}: ${r.fixes} fixes (${r.method || 'lock removal'}) → ${r.prUrl}`);
    prs++;
    totalFixes += r.fixes;
  } else if (r.status === 'skipped') {
    console.log(`  [SKIP] ${r.repo}: ${r.reason}`);
  } else if (r.status === 'clean') {
    console.log(`  [CLEAN] ${r.repo}: no fixable alerts`);
  } else {
    console.log(`  [ERR] ${r.repo}: ${r.error}`);
  }
}

console.log(`\nPRs created: ${prs} | Fixes: ${totalFixes}`);
