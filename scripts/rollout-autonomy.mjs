/**
 * Roll out git-steer autonomy to all managed repos — PACED, idempotent.
 *
 * Per repo it:
 *   1. Detects ecosystems (npm/pip/gomod/docker/github-actions) from the tree.
 *   2. Generates a grouped .github/dependabot.yml matched to that repo's stack.
 *   3. Deploys .github/workflows/dependabot-automerge.yml (the auto-merge engine).
 *   4. Enables repo settings: allow_auto_merge, Dependabot alerts, and
 *      Dependabot security updates.
 *
 * Safety (account was previously suspended for automated patterns):
 *   - DRY-RUN by default. Pass --apply to mutate.
 *   - Processes repos in small batches (BATCH_SIZE) with a delay + rate-limit
 *     check between batches. NO all-repos-at-once parallel fan-out.
 *   - Deterministic branch + PR reuse: re-running never spawns duplicate PRs.
 *   - Commits go via the Contents API, so GitHub signs them — satisfies
 *     "require signed commits" on protected branches without a local checkout.
 *
 * Usage:
 *   node scripts/rollout-autonomy.mjs               # dry-run, all repos
 *   node scripts/rollout-autonomy.mjs --apply       # execute
 *   node scripts/rollout-autonomy.mjs --apply --repos=DriveIQ,blog
 *   node scripts/rollout-autonomy.mjs --apply --limit=3
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const APPLY = process.argv.includes('--apply');
const ONLY = (process.argv.find((a) => a.startsWith('--repos=')) || '').split('=')[1];
const LIMIT = Number((process.argv.find((a) => a.startsWith('--limit=')) || '').split('=')[1]) || Infinity;

const BATCH_SIZE = 3;          // 2-3 at a time per account-safety rule
const BATCH_DELAY_MS = 15000;  // breathe between batches
const RL_FLOOR = 300;          // pause if core rate limit drops below this

const BRANCH = 'git-steer/autonomy-rollout';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- Auth (App installation token; commits are GitHub-signed) ---
const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');
const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

const __dirname = dirname(fileURLToPath(import.meta.url));
const AUTOMERGE_WORKFLOW = readFileSync(join(__dirname, '../templates/repo/dependabot-automerge.yml'), 'utf8');

// --- Ecosystem detection -------------------------------------------------
function detectEcosystems(paths) {
  const dirs = { npm: new Set(), pip: new Set(), gomod: new Set(), docker: new Set() };
  let hasActions = false;
  for (const p of paths) {
    if (p.includes('node_modules/') || p.includes('vendor/') || p.includes('.venv/')) continue;
    const base = p.split('/').pop();
    const dir = p.includes('/') ? '/' + p.split('/').slice(0, -1).join('/') : '/';
    if (base === 'package.json') dirs.npm.add(dir);
    else if (/^(requirements.*\.txt|pyproject\.toml|Pipfile|setup\.py)$/.test(base)) dirs.pip.add(dir);
    else if (base === 'go.mod') dirs.gomod.add(dir);
    else if (base === 'Dockerfile' || base.startsWith('Dockerfile.')) dirs.docker.add(dir);
    if (p.startsWith('.github/workflows/') && (p.endsWith('.yml') || p.endsWith('.yaml'))) hasActions = true;
  }
  return { dirs, hasActions };
}

function buildDependabotYaml({ dirs, hasActions }) {
  const block = (eco, dir, group, minorPatchOnly) =>
    `  - package-ecosystem: "${eco}"\n` +
    `    directory: "${dir}"\n` +
    `    schedule:\n      interval: "weekly"\n` +
    `    open-pull-requests-limit: 5\n` +
    `    groups:\n      ${group}:\n        patterns: ["*"]` +
    (minorPatchOnly ? `\n        update-types: ["minor", "patch"]` : '');

  const blocks = [];
  for (const d of [...dirs.npm].sort()) blocks.push(block('npm', d, 'npm-all', true));
  for (const d of [...dirs.pip].sort()) blocks.push(block('pip', d, 'pip-all', true));
  for (const d of [...dirs.gomod].sort()) blocks.push(block('gomod', d, 'gomod-all', true));
  for (const d of [...dirs.docker].sort()) blocks.push(block('docker', d, 'docker-all', false));
  if (hasActions) blocks.push(block('github-actions', '/', 'actions-all', false));
  if (!blocks.length) return null;

  return `# Managed by git-steer (scripts/rollout-autonomy.mjs). Grouped to cut PR volume.\nversion: 2\nupdates:\n${blocks.join('\n\n')}\n`;
}

// --- Helpers -------------------------------------------------------------
async function getTreePaths(owner, repo, branch) {
  const { data } = await octokit.request('GET /repos/{owner}/{repo}/git/trees/{ref}', {
    owner, repo, ref: branch, recursive: '1',
  });
  return (data.tree || []).filter((t) => t.type === 'blob').map((t) => t.path);
}

async function putFileOnBranch(owner, repo, path, content, branch, message) {
  let sha;
  try {
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
      owner, repo, path, ref: branch,
    });
    sha = data.sha;
    if (Buffer.from(data.content, 'base64').toString('utf8') === content) return 'unchanged';
  } catch { /* file absent */ }
  await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
    owner, repo, path, message,
    content: Buffer.from(content).toString('base64'),
    branch, ...(sha ? { sha } : {}),
  });
  return sha ? 'updated' : 'created';
}

async function enableSettings(owner, repo) {
  const out = [];
  try {
    await octokit.request('PATCH /repos/{owner}/{repo}', { owner, repo, allow_auto_merge: true });
    out.push('auto_merge');
  } catch (e) { out.push(`auto_merge:ERR(${e.status})`); }
  try {
    await octokit.request('PUT /repos/{owner}/{repo}/vulnerability-alerts', { owner, repo });
    out.push('alerts');
  } catch (e) { out.push(`alerts:ERR(${e.status})`); }
  try {
    await octokit.request('PUT /repos/{owner}/{repo}/automated-security-fixes', { owner, repo });
    out.push('security-fixes');
  } catch (e) { out.push(`security-fixes:ERR(${e.status})`); }
  return out;
}

// --- Per-repo rollout ----------------------------------------------------
async function rolloutRepo(owner, repo) {
  const { data: repoData } = await octokit.request('GET /repos/{owner}/{repo}', { owner, repo });
  const base = repoData.default_branch;

  const paths = await getTreePaths(owner, repo, base);
  const eco = detectEcosystems(paths);
  const dependabotYaml = buildDependabotYaml(eco);

  const ecoSummary = [
    ...['npm', 'pip', 'gomod', 'docker'].flatMap((k) => [...eco.dirs[k]].map((d) => `${k}${d === '/' ? '' : d}`)),
    ...(eco.hasActions ? ['github-actions'] : []),
  ].join(', ') || 'none';

  if (!APPLY) {
    return { repo, status: 'dry-run', ecosystems: ecoSummary, willDeployDependabot: !!dependabotYaml };
  }

  // Ensure deterministic branch exists from current base HEAD.
  const { data: ref } = await octokit.request('GET /repos/{owner}/{repo}/git/ref/{ref}', {
    owner, repo, ref: `heads/${base}`,
  });
  const baseSha = ref.object.sha;
  try {
    await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
      owner, repo, ref: `refs/heads/${BRANCH}`, sha: baseSha,
    });
  } catch (e) {
    if (e.status === 422) {
      // Branch exists — realign it to base so the diff stays clean.
      await octokit.request('PATCH /repos/{owner}/{repo}/git/refs/{ref}', {
        owner, repo, ref: `heads/${BRANCH}`, sha: baseSha, force: true,
      });
    } else throw e;
  }

  const changes = [];
  const wf = await putFileOnBranch(
    owner, repo, '.github/workflows/dependabot-automerge.yml', AUTOMERGE_WORKFLOW, BRANCH,
    'ci(autonomy): add Dependabot auto-merge workflow',
  );
  if (wf !== 'unchanged') changes.push(`workflow:${wf}`);

  if (dependabotYaml) {
    const db = await putFileOnBranch(
      owner, repo, '.github/dependabot.yml', dependabotYaml, BRANCH,
      'ci(autonomy): add grouped Dependabot config',
    );
    if (db !== 'unchanged') changes.push(`dependabot:${db}`);
  }

  const settings = await enableSettings(owner, repo);

  let prInfo = 'no-file-changes';
  if (changes.length) {
    // Reuse an open PR on this head instead of duplicating.
    const { data: existing } = await octokit.request('GET /repos/{owner}/{repo}/pulls', {
      owner, repo, head: `${owner}:${BRANCH}`, state: 'open',
    });
    let prNumber;
    if (existing.length) {
      prNumber = existing[0].number;
      prInfo = `reused #${prNumber}`;
    } else {
      const { data: pr } = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
        owner, repo,
        title: 'ci(autonomy): enable git-steer autonomous dependency management',
        head: BRANCH, base,
        body:
          '## git-steer autonomy rollout\n\n' +
          'Enables event-driven, self-merging dependency/security management:\n\n' +
          '- **Grouped Dependabot config** matched to this repo\'s stack\n' +
          '- **Auto-merge workflow** — approves + native auto-merges patch/minor Dependabot PRs once CI is green; majors are flagged `needs-human-merge`\n' +
          '- Repo settings enabled: allow-auto-merge, Dependabot alerts, security updates\n\n' +
          '---\nGenerated by [git-steer](https://github.com/ry-ops/git-steer) autonomy rollout',
      });
      prNumber = pr.number;
      prInfo = `opened #${prNumber}`;
    }

    // Try to land the bootstrap PR (it can't auto-merge itself yet).
    try {
      await octokit.request('PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', {
        owner, repo, pull_number: prNumber, merge_method: 'squash',
      });
      prInfo += ' (merged)';
    } catch (e) {
      prInfo += ` (merge blocked ${e.status}; left for human)`;
      try {
        await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
          owner, repo, issue_number: prNumber, labels: ['needs-human-merge'],
        });
      } catch { /* label may not exist; non-fatal */ }
    }
  }

  return { repo, status: 'applied', ecosystems: ecoSummary, changes: changes.join(', ') || 'none', pr: prInfo, settings: settings.join(', ') };
}

// --- Main: list, filter, batch ------------------------------------------
const { data: inst } = await octokit.request('GET /installation/repositories', { per_page: 100 });
let repos = inst.repositories.filter((r) => !r.archived && !r.fork);
if (ONLY) {
  const want = new Set(ONLY.split(','));
  repos = repos.filter((r) => want.has(r.name));
}
repos = repos.slice(0, LIMIT);

console.log(`${APPLY ? 'APPLYING' : 'DRY-RUN'} autonomy rollout to ${repos.length} repo(s), ${BATCH_SIZE}/batch\n`);

const results = [];
for (let i = 0; i < repos.length; i += BATCH_SIZE) {
  const batch = repos.slice(i, i + BATCH_SIZE);
  const settled = await Promise.allSettled(
    batch.map((r) => rolloutRepo(r.owner.login, r.name)),
  );
  for (let j = 0; j < settled.length; j++) {
    const s = settled[j];
    if (s.status === 'fulfilled') {
      const v = s.value;
      console.log(`  [${v.status}] ${v.repo} — eco: ${v.ecosystems}` +
        (v.changes ? ` | ${v.changes}` : '') + (v.pr ? ` | PR: ${v.pr}` : '') +
        (v.settings ? ` | settings: ${v.settings}` : ''));
      results.push(v);
    } else {
      console.log(`  [ERROR] ${batch[j].name} — ${s.reason?.message || s.reason}`);
      results.push({ repo: batch[j].name, status: 'error' });
    }
  }

  if (i + BATCH_SIZE < repos.length) {
    const { data: rl } = await octokit.request('GET /rate_limit');
    const remaining = rl.resources.core.remaining;
    console.log(`  ...batch done. core rate limit: ${remaining} remaining`);
    if (remaining < RL_FLOOR) {
      const waitMs = Math.max(0, rl.resources.core.reset * 1000 - Date.now()) + 5000;
      console.log(`  rate limit low — sleeping ${Math.round(waitMs / 1000)}s until reset`);
      await sleep(waitMs);
    } else {
      await sleep(BATCH_DELAY_MS);
    }
  }
}

console.log(`\n=== SUMMARY (${APPLY ? 'applied' : 'dry-run'}) ===`);
const by = (s) => results.filter((r) => r.status === s).length;
console.log(`applied: ${by('applied')} | dry-run: ${by('dry-run')} | errors: ${by('error')}`);
if (!APPLY) console.log('\nRe-run with --apply to execute. Add --limit=3 or --repos=a,b to scope.');
