/**
 * Lightweight GitHub client using token auth only.
 * No Keychain, no App auth, no keytar dependency.
 * Used by the web server entry point.
 */

import { Octokit } from 'octokit';

export interface SecurityAlert {
  /** Which GitHub alert class this finding came from. */
  source: 'dependabot' | 'code-scanning';
  alertNumber: number;
  severity: string;
  package: string;
  ecosystem: string;
  cve: string | null;
  ghsaId: string | null;
  summary: string;
  description: string;
  currentVersion: string;
  fixVersion: string | null;
  manifestPath: string;
  state: string;
  createdAt: string;
  url: string;
}

export class TokenGitHubClient {
  private octokit: Octokit;
  private _token: string;

  constructor(token: string) {
    this._token = token;
    this.octokit = new Octokit({ auth: token });
  }

  isAuthenticated(): boolean { return true; }

  getOctokit(): Octokit { return this.octokit; }

  async getRateLimit() {
    const { data } = await this.octokit.rest.rateLimit.get();
    return data.rate;
  }

  async getInstallationToken(): Promise<string> {
    return this._token;
  }

  /**
   * Fetch ALL open security findings for a repo, across both GitHub alert
   * classes — Dependabot AND Code Scanning — fully paginated.
   *
   * Per ADR-004 ("report ALL"), every detected issue must surface. The old
   * implementation queried Dependabot only and capped at one 100-item page,
   * so it silently dropped code-scanning findings entirely and truncated any
   * repo with >100 dependency alerts. Both classes are now merged.
   *
   * Code-scanning findings have no patched version, so `fixVersion` is null —
   * the dependency-bump fix paths filter on `fixVersion` and therefore skip
   * them automatically, routing them to the manual/VEX remediation path.
   */
  async getSecurityAlertsDetailed(owner: string, repo: string): Promise<SecurityAlert[]> {
    const [dependabot, codeScanning] = await Promise.all([
      this.fetchDependabotAlerts(owner, repo),
      this.fetchCodeScanningAlerts(owner, repo),
    ]);
    return [...dependabot, ...codeScanning];
  }

  /** Dependabot dependency alerts (open, fully paginated). */
  private async fetchDependabotAlerts(owner: string, repo: string): Promise<SecurityAlert[]> {
    try {
      const data = await this.octokit.paginate('GET /repos/{owner}/{repo}/dependabot/alerts', {
        owner,
        repo,
        state: 'open',
        per_page: 100,
      });

      return data.map((a: any) => ({
        source: 'dependabot' as const,
        alertNumber: a.number,
        severity: (a.security_vulnerability?.severity ?? a.security_advisory?.severity ?? 'unknown').toLowerCase(),
        package: a.security_vulnerability?.package?.name ?? a.dependency?.package?.name ?? 'unknown',
        ecosystem: a.security_vulnerability?.package?.ecosystem ?? a.dependency?.package?.ecosystem ?? 'unknown',
        cve: a.security_advisory?.cve_id ?? null,
        ghsaId: a.security_advisory?.ghsa_id ?? null,
        summary: a.security_advisory?.summary ?? '',
        description: a.security_advisory?.description ?? '',
        currentVersion: a.security_vulnerability?.vulnerable_version_range ?? '',
        fixVersion: a.security_vulnerability?.first_patched_version?.identifier ?? null,
        manifestPath: a.dependency?.manifest_path ?? '',
        state: a.state,
        createdAt: a.created_at,
        url: a.html_url,
      }));
    } catch (err: any) {
      // Dependabot alerts might be disabled or we lack permissions
      if (err.status === 403 || err.status === 404) {
        return [];
      }
      throw err;
    }
  }

  /** Code-scanning (CodeQL/SAST) alerts (open, fully paginated). */
  private async fetchCodeScanningAlerts(owner: string, repo: string): Promise<SecurityAlert[]> {
    try {
      const data = await this.octokit.paginate('GET /repos/{owner}/{repo}/code-scanning/alerts', {
        owner,
        repo,
        state: 'open',
        per_page: 100,
      });

      return data.map((a: any) => ({
        source: 'code-scanning' as const,
        alertNumber: a.number,
        // security_severity_level is critical/high/medium/low; rule.severity (error/warning/note) is the fallback
        severity: (a.rule?.security_severity_level ?? a.rule?.severity ?? 'unknown').toLowerCase(),
        package: a.rule?.id ?? 'unknown',
        ecosystem: 'code-scanning',
        cve: null,
        ghsaId: null,
        summary: a.rule?.description ?? a.rule?.name ?? '',
        description: a.most_recent_instance?.message?.text ?? a.rule?.full_description ?? '',
        currentVersion: '',
        fixVersion: null,
        manifestPath: a.most_recent_instance?.location?.path ?? '',
        state: a.state,
        createdAt: a.created_at,
        url: a.html_url,
      }));
    } catch (err: any) {
      // Code scanning not enabled, no analysis yet, or no permission
      if (err.status === 403 || err.status === 404) {
        return [];
      }
      throw err;
    }
  }

  async commitFiles(owner: string, repo: string, opts: {
    branch: string;
    message: string;
    files: { path: string; content: string }[];
    createBranch?: boolean;
    baseBranch?: string;
  }): Promise<{ sha: string; url: string }> {
    // Simplified — use Contents API for single file commits
    for (const file of opts.files) {
      let sha: string | undefined;
      try {
        const { data } = await this.octokit.rest.repos.getContent({ owner, repo, path: file.path, ref: opts.branch });
        sha = (data as { sha: string }).sha;
      } catch { /* file doesn't exist */ }

      await this.octokit.rest.repos.createOrUpdateFileContents({
        owner, repo,
        path: file.path,
        message: opts.message,
        content: Buffer.from(file.content).toString('base64'),
        branch: opts.branch,
        ...(sha ? { sha } : {}),
      });
    }
    return { sha: 'committed', url: `https://github.com/${owner}/${repo}` };
  }
}
