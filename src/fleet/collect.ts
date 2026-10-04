/**
 * Fleet collector (ADR-009 Layer 2).
 *
 * Reads every repo the reporter App is installed on, through GET requests
 * only. Coverage is recorded before findings, and a tool's findings are only
 * read when that tool is on (C-009-001). A failure on one repo is recorded on
 * that repo and never stops the run.
 */

import { App, Octokit } from 'octokit';
import pLimit from 'p-limit';
import {
  addSeverity, ageInDays, branchProtectionState, codeScanningState, dependabotAlertsState,
  emptyCounts, secretScanningState, securityUpdatesState, settingState,
} from './classify.js';
import { SCHEMA } from './types.js';
import type { Coverage, FleetStatus, Findings, RepoStatus } from './types.js';

const STALE_PR_DAYS = 14;
const REPO_CONCURRENCY = 4;

interface Answer<T> {
  status: number;
  message: string;
  data: T | null;
}

interface InstallationRepo {
  name: string;
  full_name: string;
  private: boolean;
  archived: boolean;
  default_branch: string;
  html_url: string;
  owner: { login: string };
}

function errorOf(err: unknown): { status: number; message: string } {
  const e = err as { status?: number; message?: string; response?: { data?: { message?: string } } };
  return { status: e.status ?? 0, message: e.response?.data?.message ?? e.message ?? '' };
}

/** One GET that never throws. */
async function get<T>(octokit: Octokit, route: string, params: Record<string, unknown>): Promise<Answer<T>> {
  try {
    const res = await octokit.request(route, params);
    return { status: 200, message: '', data: res.data as T };
  } catch (err) {
    return { ...errorOf(err), data: null };
  }
}

/** A paginated GET that never throws: null on failure, or [] on a 404 when `emptyOn404` is set. */
async function getAll<T>(
  octokit: Octokit, route: string, params: Record<string, unknown>, emptyOn404 = false,
): Promise<T[] | null> {
  try {
    return (await octokit.paginate(route, { per_page: 100, ...params })) as T[];
  } catch (err) {
    return emptyOn404 && errorOf(err).status === 404 ? [] : null;
  }
}

async function readCoverage(octokit: Octokit, owner: string, repo: string, branch: string): Promise<Coverage> {
  const p = { owner, repo, per_page: 1 };
  const [dep, code, secret, info, rules, classic, fixes] = await Promise.all([
    get(octokit, 'GET /repos/{owner}/{repo}/dependabot/alerts', p),
    get(octokit, 'GET /repos/{owner}/{repo}/code-scanning/alerts', p),
    get(octokit, 'GET /repos/{owner}/{repo}/secret-scanning/alerts', p),
    get<{ security_and_analysis?: Record<string, { status?: string } | undefined> }>(octokit, 'GET /repos/{owner}/{repo}', { owner, repo }),
    get<unknown[]>(octokit, 'GET /repos/{owner}/{repo}/rules/branches/{branch}', { owner, repo, branch }),
    get(octokit, 'GET /repos/{owner}/{repo}/branches/{branch}/protection', { owner, repo, branch }),
    get<{ enabled?: boolean; paused?: boolean }>(octokit, 'GET /repos/{owner}/{repo}/automated-security-fixes', { owner, repo }),
  ]);
  // No analysis yet: is CodeQL default setup configured (scan pending, or nothing to scan)?
  const setup = code.status === 404
    ? await get<{ state?: string }>(octokit, 'GET /repos/{owner}/{repo}/code-scanning/default-setup', { owner, repo })
    : null;
  const sa = info.data?.security_and_analysis;
  return {
    dependabotAlerts: dependabotAlertsState(dep.status, dep.message),
    dependabotSecurityUpdates: securityUpdatesState(fixes, sa?.dependabot_security_updates?.status),
    codeScanning: codeScanningState(code.status, code.message, setup?.data?.state),
    secretScanning: secretScanningState(secret.status, secret.message),
    pushProtection: settingState(sa?.secret_scanning_push_protection?.status),
    branchProtection: branchProtectionState(
      { status: rules.status, message: rules.message, count: rules.data?.length ?? 0 },
      { status: classic.status, message: classic.message },
    ),
  };
}

interface DependabotAlert {
  number: number;
  html_url: string;
  dismissed_comment?: string | null;
  dependency?: { package?: { name?: string } };
  security_advisory?: { ghsa_id?: string; severity?: string };
  security_vulnerability?: { first_patched_version?: { identifier?: string } | null };
}

async function readFindings(
  octokit: Octokit, owner: string, repo: string, coverage: Coverage, now: Date, errors: string[],
): Promise<Findings> {
  const findings: Findings = {
    dependabot: null, codeScanning: null, secretScanning: null,
    noPatch: [], staleDependabotPrs: [], undocumentedDismissals: [],
  };

  if (coverage.dependabotAlerts === 'on') {
    const open = await getAll<DependabotAlert>(octokit, 'GET /repos/{owner}/{repo}/dependabot/alerts', { owner, repo, state: 'open' });
    if (open) {
      findings.dependabot = emptyCounts();
      for (const a of open) {
        addSeverity(findings.dependabot, a.security_advisory?.severity);
        if (!a.security_vulnerability?.first_patched_version?.identifier) {
          findings.noPatch.push({
            number: a.number, ghsa: a.security_advisory?.ghsa_id ?? '', package: a.dependency?.package?.name ?? '',
            severity: a.security_advisory?.severity ?? '', url: a.html_url,
          });
        }
      }
    } else {
      errors.push('dependabot alerts: read failed');
    }
    const dismissed = await getAll<DependabotAlert>(octokit, 'GET /repos/{owner}/{repo}/dependabot/alerts', { owner, repo, state: 'dismissed' });
    for (const a of dismissed ?? []) {
      if (!a.dismissed_comment?.trim()) {
        findings.undocumentedDismissals.push({
          number: a.number, ghsa: a.security_advisory?.ghsa_id ?? '', package: a.dependency?.package?.name ?? '', url: a.html_url,
        });
      }
    }
  }

  if (coverage.codeScanning === 'on') {
    const open = await getAll<{ rule?: { security_severity_level?: string | null; severity?: string | null } }>(
      octokit, 'GET /repos/{owner}/{repo}/code-scanning/alerts', { owner, repo, state: 'open' }, true); // 404 = no analysis yet
    if (open) {
      findings.codeScanning = emptyCounts();
      for (const a of open) addSeverity(findings.codeScanning, a.rule?.security_severity_level ?? a.rule?.severity);
    } else {
      errors.push('code scanning alerts: read failed');
    }
  }

  if (coverage.secretScanning === 'on') {
    const open = await getAll<unknown>(octokit, 'GET /repos/{owner}/{repo}/secret-scanning/alerts', { owner, repo, state: 'open' });
    if (open) findings.secretScanning = open.length;
    else errors.push('secret scanning alerts: read failed');
  }

  const pulls = await getAll<{ number: number; title: string; created_at: string; html_url: string; user?: { login?: string } }>(
    octokit, 'GET /repos/{owner}/{repo}/pulls', { owner, repo, state: 'open' });
  for (const pr of pulls ?? []) {
    const age = ageInDays(pr.created_at, now);
    if (pr.user?.login === 'dependabot[bot]' && age > STALE_PR_DAYS) {
      findings.staleDependabotPrs.push({ number: pr.number, title: pr.title, ageDays: age, url: pr.html_url });
    }
  }
  if (!pulls) errors.push('pull requests: read failed');

  return findings;
}

async function readRepo(octokit: Octokit, r: InstallationRepo, now: Date): Promise<RepoStatus> {
  const owner = r.owner.login;
  const errors: string[] = [];
  const coverage = await readCoverage(octokit, owner, r.name, r.default_branch);
  const findings = await readFindings(octokit, owner, r.name, coverage, now, errors);
  const cfg = await get(octokit, 'GET /repos/{owner}/{repo}/contents/{path}', { owner, repo: r.name, path: '.github/git-steer.yml' });
  return {
    repo: r.full_name, owner, private: r.private, defaultBranch: r.default_branch, url: r.html_url,
    coverage, findings,
    config: cfg.status === 200 ? 'present' : cfg.status === 404 ? 'absent' : 'unknown',
    errors,
  };
}

/** Reads the whole fleet the App can see. Archived repos are skipped (ADR-009: listed, not scored). */
export async function collectFleet(app: App, now = new Date()): Promise<FleetStatus> {
  const { data: appInfo } = await app.octokit.request('GET /app');
  const status: FleetStatus = {
    schema: SCHEMA, generatedAt: now.toISOString(), app: appInfo?.slug ?? 'unknown', owners: [], repos: [],
  };
  const limit = pLimit(REPO_CONCURRENCY);

  for await (const { installation } of app.eachInstallation.iterator()) {
    const account = (installation.account as { login?: string } | null)?.login ?? String(installation.id);
    if (installation.suspended_at) {
      status.owners.push({ account, repos: 0 });
      continue;
    }
    const octokit = await app.getInstallationOctokit(installation.id);
    const repos = (await octokit.paginate('GET /installation/repositories', { per_page: 100 })) as unknown as InstallationRepo[];
    const active = repos.filter((r) => !r.archived);
    status.owners.push({ account, repos: active.length });
    status.repos.push(...(await Promise.all(active.map((r) => limit(() => readRepo(octokit, r, now))))));
  }

  status.repos.sort((a, b) => a.repo.localeCompare(b.repo));
  return status;
}

/** C-009-003: fleet data may only be produced inside a private repo. */
export async function isRunningInPrivateRepo(token: string | undefined, repository: string | undefined): Promise<boolean> {
  const [owner, repo] = (repository ?? '').split('/');
  if (!token || !owner || !repo) return false;
  try {
    const { data } = await new Octokit({ auth: token }).request('GET /repos/{owner}/{repo}', { owner, repo });
    return data.private === true;
  } catch {
    return false;
  }
}
