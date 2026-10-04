/**
 * GitHub App permissions audit (ADR-009)
 *
 * Read-only. For every installation of one GitHub App, records what it is
 * allowed to do and which repos it covers, then probes each repo with GET
 * requests to see what it can actually read: Dependabot, code-scanning and
 * secret-scanning alerts, branch rules and protection, security settings and
 * .github/git-steer.yml.
 *
 * The output names repos and says which have detectors off, so it is fleet
 * data (C-009-003): before anything else, the script asks GitHub whether the
 * repo running it is private, and refuses to run if it isn't.
 *
 * Writes app-audit.json and app-audit.md (a summary) to the working directory.
 *
 * Env vars:
 *   APP_ID            - GitHub App ID
 *   APP_PRIVATE_KEY   - GitHub App private key (PEM)
 *   GITHUB_TOKEN      - the running repo's token, used only to read its visibility
 *   GITHUB_REPOSITORY - set by Actions
 */

import { App, Octokit } from 'octokit';
import { realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';


// ===== Probes =====

/** One GET; returns a status word, never throws. */
async function probe(octokit, route, params, classify) {
  try {
    const res = await octokit.request(route, params);
    return classify ? classify(200, '', res.data) : 'on';
  } catch (err) {
    const status = err.status ?? 0;
    const message = err.response?.data?.message ?? err.message ?? '';
    if (/not accessible by integration/i.test(message)) return 'no-permission';
    if (classify) return classify(status, message);
    return `error:${status}`;
  }
}

/** GitHub's answers when a feature needs a paid plan, not a setting change. */
const planLimited = (message) => /upgrade to github pro|advanced security must be enabled/i.test(message);

const dependabot = (status, message) => {
  if (status === 200) return 'on';
  if (status === 403 && /disabled/i.test(message)) return 'off';
  return `error:${status}`;
};

const codeScanning = (status, message) => {
  if (status === 200) return 'on';
  if (status === 404) return 'off'; // no analysis found
  if (status === 403 && (planLimited(message) || /code security/i.test(message))) return 'unavailable';
  if (status === 403 && /disabled|not enabled/i.test(message)) return 'off';
  return `error:${status}`;
};

const secretScanning = (status, message) => {
  if (status === 200) return 'on';
  if (status === 404) return 'off'; // disabled, or not available for this repo
  if (status === 403 && /disabled|not enabled/i.test(message)) return 'off';
  return `error:${status}`;
};

const present = (status) => (status === 200 ? 'present' : status === 404 ? 'absent' : `error:${status}`);

async function auditRepo(octokit, repo) {
  const owner = repo.owner.login;
  const name = repo.name;
  const branch = repo.default_branch;
  const p = { owner, repo: name, per_page: 1 };

  const row = { repo: repo.full_name, private: repo.private, archived: repo.archived, defaultBranch: branch };
  if (repo.archived) return row;

  row.dependabotAlerts = await probe(octokit, 'GET /repos/{owner}/{repo}/dependabot/alerts', p, dependabot);
  row.codeScanning = await probe(octokit, 'GET /repos/{owner}/{repo}/code-scanning/alerts', p, codeScanning);
  row.secretScanning = await probe(octokit, 'GET /repos/{owner}/{repo}/secret-scanning/alerts', p, secretScanning);

  // Rulesets that apply to the default branch (readable with metadata only).
  row.branchRules = await probe(
    octokit, 'GET /repos/{owner}/{repo}/rules/branches/{branch}', { owner, repo: name, branch },
    (status, message, data) => {
      if (status === 200) return data.length ? data.map((r) => r.type).sort().join(',') : 'none';
      return status === 403 && planLimited(message) ? 'unavailable' : `error:${status}`;
    },
  );
  row.classicProtection = await probe(
    octokit, 'GET /repos/{owner}/{repo}/branches/{branch}/protection', { owner, repo: name, branch },
    (status, message) => {
      if (status === 200) return 'present';
      if (status === 404) return 'absent';
      return status === 403 && planLimited(message) ? 'unavailable' : `error:${status}`;
    },
  );
  row.branchProtection = branchProtection(row);

  // security_and_analysis is only returned with administration read.
  row.securitySettings = await probe(
    octokit, 'GET /repos/{owner}/{repo}', { owner, repo: name },
    (status, _m, data) => {
      if (status !== 200) return `error:${status}`;
      const sa = data.security_and_analysis;
      if (!sa) return 'not-visible';
      return Object.fromEntries(Object.entries(sa).map(([k, v]) => [k, v?.status ?? 'unknown']));
    },
  );

  // Dependabot security updates (the fix PRs) and push protection are only
  // visible in security_and_analysis; GitHub omits it for some private repos.
  const sa = typeof row.securitySettings === 'object' ? row.securitySettings : null;
  row.dependabotSecurityUpdates = sa ? onOff(sa.dependabot_security_updates) : 'not-visible';
  row.pushProtection = sa ? onOff(sa.secret_scanning_push_protection) : 'not-visible';

  row.config = await probe(
    octokit, 'GET /repos/{owner}/{repo}/contents/{path}', { owner, repo: name, path: '.github/git-steer.yml' },
    present,
  );
  return row;
}

export function onOff(status) {
  if (status === 'enabled') return 'on';
  if (status === 'disabled') return 'off';
  return status ?? 'unknown';
}

/** Combined view of rulesets and classic protection on the default branch. */
export function branchProtection(row) {
  const rules = String(row.branchRules ?? '');
  if (row.classicProtection === 'present' || (rules && rules !== 'none' && !rules.startsWith('error') && rules !== 'unavailable')) return 'on';
  if (row.classicProtection === 'unavailable' || rules === 'unavailable') return 'unavailable';
  if (row.classicProtection === 'absent' && rules === 'none') return 'off';
  return 'unknown';
}

// ===== Main =====

/** C-009-003: the output is fleet data, so only a private repo may produce it. */
async function assertRunningInPrivateRepo() {
  const { GITHUB_TOKEN, GITHUB_REPOSITORY } = process.env;
  const [owner, repo] = (GITHUB_REPOSITORY || '').split('/');
  let isPrivate = false;
  if (GITHUB_TOKEN && owner && repo) {
    try {
      const { data } = await new Octokit({ auth: GITHUB_TOKEN }).request('GET /repos/{owner}/{repo}', { owner, repo });
      isPrivate = data.private === true;
    } catch {
      isPrivate = false;
    }
  }
  if (!isPrivate) {
    console.error('Refusing to run: the audit names repos and their gaps, so it must run in a private repo (ADR-009 C-009-003).');
    process.exit(1);
  }
}

async function main() {
  await assertRunningInPrivateRepo();

  const { APP_ID, APP_PRIVATE_KEY } = process.env;
  if (!APP_ID || !APP_PRIVATE_KEY) {
    console.error('APP_ID and APP_PRIVATE_KEY are required.');
    process.exit(1);
  }
  const app = new App({ appId: APP_ID, privateKey: APP_PRIVATE_KEY });
  const { data: appInfo } = await app.octokit.request('GET /app');
  const report = {
    generatedAt: new Date().toISOString(),
    app: { slug: appInfo.slug, id: appInfo.id, permissions: appInfo.permissions },
    installations: [],
  };

  for await (const { installation } of app.eachInstallation.iterator()) {
    const entry = {
      id: installation.id,
      account: installation.account.login,
      accountType: installation.account.type,
      repositorySelection: installation.repository_selection,
      suspended: Boolean(installation.suspended_at),
      permissions: installation.permissions,
      writePermissions: Object.entries(installation.permissions)
        .filter(([, level]) => level === 'write' || level === 'admin')
        .map(([perm, level]) => `${perm}:${level}`)
        .sort(),
      repos: [],
    };
    console.log(`Installation ${entry.account} (${entry.repositorySelection})`);

    if (!entry.suspended) {
      const octokit = await app.getInstallationOctokit(installation.id);
      const repos = await octokit.paginate('GET /installation/repositories', { per_page: 100 });
      for (const repo of repos) {
        entry.repos.push(await auditRepo(octokit, repo));
      }
    }
    report.installations.push(entry);
  }

  writeFileSync('app-audit.json', JSON.stringify(report, null, 2));
  writeFileSync('app-audit.md', toMarkdown(report));
  console.log('Wrote app-audit.json and app-audit.md');
}

// ===== Summary =====

const CHECKS = [
  ['dependabotAlerts', 'Dependabot alerts'],
  ['dependabotSecurityUpdates', 'Dependabot security updates (fix PRs)'],
  ['codeScanning', 'Code scanning'],
  ['secretScanning', 'Secret scanning'],
  ['pushProtection', 'Push protection'],
  ['branchProtection', 'Branch protection (rules or classic)'],
  ['config', '.github/git-steer.yml'],
];

function count(rows, key) {
  const out = {};
  for (const r of rows) out[r[key] ?? 'n/a'] = (out[r[key] ?? 'n/a'] || 0) + 1;
  return Object.entries(out).sort().map(([k, n]) => `${k} ${n}`).join(' · ') || '–';
}

export function toMarkdown(report) {
  const lines = [`## App audit: ${report.app.slug}`, '', `Generated ${report.generatedAt}`, ''];
  lines.push('| Account | Selection | Repos | Write permissions |', '|---|---|---|---|');
  for (const i of report.installations) {
    lines.push(`| ${i.account}${i.suspended ? ' (suspended)' : ''} | ${i.repositorySelection} | ${i.repos.length} | ${i.writePermissions.length ? i.writePermissions.join(', ') : 'none'} |`);
  }
  const rows = report.installations.flatMap((i) => i.repos).filter((r) => !r.archived);
  const pub = rows.filter((r) => !r.private);
  const priv = rows.filter((r) => r.private);

  lines.push('', `### Coverage across ${rows.length} active repos (${pub.length} public, ${priv.length} private)`, '');
  lines.push('"unavailable": GitHub says the repo\'s plan doesn\'t include it. "off": GitHub reports it disabled (on public repos all of these are free to turn on). "not-visible": GitHub doesn\'t return the setting for this repo.', '');
  lines.push('| Check | Public | Private |', '|---|---|---|');
  for (const [key, label] of CHECKS) lines.push(`| ${label} | ${count(pub, key)} | ${count(priv, key)} |`);

  // Everything below is free on public repos, so each gap is a setting.
  const free = [
    ['dependabotSecurityUpdates', 'Dependabot security updates off'],
    ['codeScanning', 'Code scanning off'],
    ['secretScanning', 'Secret scanning off'],
    ['pushProtection', 'Push protection off'],
    ['branchProtection', 'No branch protection'],
  ];
  lines.push('', '### Free to fix on public repos', '', '| Gap | Repos |', '|---|---|');
  for (const [key, label] of free) lines.push(`| ${label} | ${pub.filter((r) => r[key] === 'off').length} |`);

  const short = { on: '✅', off: '❌', unavailable: '—', 'not-visible': '?', 'no-permission': '🔒' };
  const cell = (v) => short[v] ?? String(v ?? '?');
  const gaps = rows.filter((r) => CHECKS.slice(0, 6).some(([k]) => r[k] === 'off'));
  if (gaps.length) {
    lines.push('', `### Repos with something turned off (${gaps.length})`, '');
    lines.push('✅ on · ❌ off · — not on this plan · ? not visible', '');
    lines.push('| Repo | Vis | Alerts | Fix PRs | Code | Secrets | Push prot. | Branch |', '|---|---|---|---|---|---|---|---|');
    for (const r of gaps) {
      lines.push(`| ${r.repo} | ${r.private ? 'private' : 'public'} | ${CHECKS.slice(0, 6).map(([k]) => cell(r[k])).join(' | ')} |`);
    }
  }
  return lines.join('\n') + '\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
