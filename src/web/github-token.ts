/**
 * Lightweight GitHub client using token auth only.
 * No Keychain, no App auth, no keytar dependency.
 * Used by the web server entry point.
 */

import { Octokit } from 'octokit';

export interface SecurityAlert {
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
   * Fetch Dependabot security alerts for a repo via REST API.
   * Returns normalized alert objects.
   */
  async getSecurityAlertsDetailed(owner: string, repo: string): Promise<SecurityAlert[]> {
    try {
      const { data } = await this.octokit.rest.dependabot.listAlertsForRepo({
        owner,
        repo,
        state: 'open',
        per_page: 100,
      });

      return data.map((a: any) => ({
        alertNumber: a.number,
        severity: a.security_vulnerability?.severity ?? a.security_advisory?.severity ?? 'unknown',
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

  // ── Security Fix PR Methods ──────────────────────────────────────────

  /**
   * Create a new branch from the repo's default branch HEAD.
   */
  async createFixBranch(owner: string, repo: string, branchName: string): Promise<void> {
    // Get the default branch
    const { data: repoData } = await this.octokit.rest.repos.get({ owner, repo });
    const defaultBranch = repoData.default_branch;

    // Get HEAD SHA of the default branch
    const { data: refData } = await this.octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`,
    });
    const sha = refData.object.sha;

    // Create the new branch
    await this.octokit.rest.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${branchName}`,
      sha,
    });
  }

  /**
   * Create a pull request.
   */
  async createFixPR(owner: string, repo: string, opts: {
    title: string;
    body: string;
    head: string;
    base: string;
  }): Promise<{ number: number; url: string }> {
    const { data } = await this.octokit.rest.pulls.create({
      owner,
      repo,
      title: opts.title,
      body: opts.body,
      head: opts.head,
      base: opts.base,
    });
    return { number: data.number, url: data.html_url };
  }

  /**
   * Merge a pull request. Defaults to squash merge.
   */
  async mergePR(owner: string, repo: string, prNumber: number, method: 'squash' | 'merge' = 'squash'): Promise<boolean> {
    try {
      await this.octokit.rest.pulls.merge({
        owner,
        repo,
        pull_number: prNumber,
        merge_method: method,
      });
      return true;
    } catch (err: any) {
      console.error(`[git-steer] Failed to merge PR #${prNumber}: ${err.message}`);
      return false;
    }
  }

  /**
   * Update a dependency version in package.json on a given branch.
   * Returns the commit SHA. Only updates package.json — the PR description
   * notes that npm install should be run after merge to regenerate the lock file.
   */
  async updatePackageJson(
    owner: string,
    repo: string,
    branch: string,
    packageName: string,
    newVersion: string,
  ): Promise<string> {
    // Get current package.json from the branch
    const { data: fileData } = await this.octokit.rest.repos.getContent({
      owner,
      repo,
      path: 'package.json',
      ref: branch,
    });

    if (Array.isArray(fileData) || fileData.type !== 'file' || !('content' in fileData)) {
      throw new Error('package.json is not a file or has no content');
    }

    const content = Buffer.from(fileData.content, 'base64').toString('utf-8');
    const pkg = JSON.parse(content);

    // Find and update the dependency in all possible sections
    let found = false;
    for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      if (pkg[section]?.[packageName]) {
        pkg[section][packageName] = newVersion;
        found = true;
      }
    }

    if (!found) {
      throw new Error(`Package "${packageName}" not found in any dependency section of package.json`);
    }

    // Commit the updated package.json
    const updatedContent = JSON.stringify(pkg, null, 2) + '\n';
    const { data: commitData } = await this.octokit.rest.repos.createOrUpdateFileContents({
      owner,
      repo,
      path: 'package.json',
      message: `fix(deps): upgrade ${packageName} to ${newVersion}`,
      content: Buffer.from(updatedContent).toString('base64'),
      branch,
      sha: fileData.sha,
    });

    return commitData.commit.sha ?? 'committed';
  }

  /**
   * Full security fix flow: create branch, update package.json, create PR.
   */
  async createSecurityFixPR(owner: string, repo: string, alert: SecurityAlert): Promise<{
    branch: string;
    prNumber: number;
    prUrl: string;
  }> {
    const safePkg = alert.package.replace(/[^a-zA-Z0-9._-]/g, '-');
    const branch = `security/fix-${safePkg}-${alert.alertNumber}`;

    // 1. Create branch from default branch HEAD
    await this.createFixBranch(owner, repo, branch);

    // 2. Update package.json with the fix version
    if (!alert.fixVersion) {
      throw new Error(`Alert #${alert.alertNumber} has no fix version available`);
    }
    await this.updatePackageJson(owner, repo, branch, alert.package, alert.fixVersion);

    // 3. Build PR title and body
    const cveLabel = alert.cve ?? alert.ghsaId ?? `alert-${alert.alertNumber}`;
    const title = `fix(security): upgrade ${alert.package} to ${alert.fixVersion} (${cveLabel})`;

    const nvdLink = alert.cve
      ? `- **NVD**: https://nvd.nist.gov/vuln/detail/${alert.cve}`
      : '';

    const body = [
      `## Security Fix`,
      ``,
      `Upgrades **${alert.package}** to \`${alert.fixVersion}\` to resolve a ${alert.severity} severity vulnerability.`,
      ``,
      `### Details`,
      ``,
      alert.cve ? `- **CVE**: ${alert.cve}` : '',
      alert.ghsaId ? `- **GHSA**: ${alert.ghsaId}` : '',
      `- **Severity**: ${alert.severity}`,
      `- **Summary**: ${alert.summary}`,
      `- **Vulnerable range**: ${alert.currentVersion}`,
      `- **Fix version**: ${alert.fixVersion}`,
      nvdLink,
      alert.url ? `- **Alert**: ${alert.url}` : '',
      ``,
      `### Post-merge`,
      ``,
      `> **Note**: Run \`npm install\` after merging to regenerate \`package-lock.json\`.`,
      ``,
      `---`,
      `*Automated by git-steer security fix*`,
    ].filter(Boolean).join('\n');

    // 4. Get default branch name for PR base
    const { data: repoData } = await this.octokit.rest.repos.get({ owner, repo });

    // 5. Create the PR
    const pr = await this.createFixPR(owner, repo, {
      title,
      body,
      head: branch,
      base: repoData.default_branch,
    });

    return {
      branch,
      prNumber: pr.number,
      prUrl: pr.url,
    };
  }
}
