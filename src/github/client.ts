/**
 * GitHub API client
 * 
 * Wraps Octokit with GitHub App authentication.
 * Provides typed methods for all git-steer operations.
 */

import { App, Octokit } from 'octokit';

export interface GitHubClientConfig {
  appId: string;
  privateKey: string;
  installationId: string;
}

export interface RepoInfo {
  owner: string;
  name: string;
  fullName: string;
  private: boolean;
  defaultBranch: string;
  archived: boolean;
}

export interface BranchInfo {
  name: string;
  protected: boolean;
  lastCommit: string;
  lastCommitDate: Date;
  merged: boolean;
}

export class GitHubClient {
  private app: App;
  private octokit: Octokit | null = null;
  private installationId: number;
  private authenticated = false;

  constructor(config: GitHubClientConfig) {
    this.app = new App({
      appId: config.appId,
      privateKey: config.privateKey,
    });
    this.installationId = parseInt(config.installationId);
  }

  /**
   * Authenticate and get installation token
   */
  async authenticate(): Promise<void> {
    this.octokit = await this.app.getInstallationOctokit(this.installationId);
    this.authenticated = true;
  }

  isAuthenticated(): boolean {
    return this.authenticated;
  }

  private ensureAuth(): Octokit {
    if (!this.octokit) {
      throw new Error('Not authenticated. Call authenticate() first.');
    }
    return this.octokit;
  }

  // ========== Rate Limits ==========

  async getRateLimit(): Promise<{ remaining: number; limit: number; reset: Date }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('GET /rate_limit');
    return {
      remaining: data.resources.core.remaining,
      limit: data.resources.core.limit,
      reset: new Date(data.resources.core.reset * 1000),
    };
  }

  // ========== Repository Operations ==========

  async listRepos(): Promise<RepoInfo[]> {
    const octokit = this.ensureAuth();
    const repos: RepoInfo[] = [];

    for await (const response of octokit.paginate.iterator(
      'GET /installation/repositories'
    )) {
      for (const repo of response.data) {
        repos.push({
          owner: repo.owner.login,
          name: repo.name,
          fullName: repo.full_name,
          private: repo.private,
          defaultBranch: repo.default_branch,
          archived: repo.archived,
        });
      }
    }

    return repos;
  }

  async createRepo(options: {
    name: string;
    description?: string;
    private?: boolean;
    template?: { owner: string; repo: string };
  }): Promise<RepoInfo> {
    const octokit = this.ensureAuth();

    let response;
    if (options.template) {
      response = await octokit.request(
        'POST /repos/{template_owner}/{template_repo}/generate',
        {
          template_owner: options.template.owner,
          template_repo: options.template.repo,
          name: options.name,
          description: options.description,
          private: options.private ?? true,
        }
      );
    } else {
      response = await octokit.request('POST /user/repos', {
        name: options.name,
        description: options.description,
        private: options.private ?? true,
        auto_init: true,
      });
    }

    return {
      owner: response.data.owner.login,
      name: response.data.name,
      fullName: response.data.full_name,
      private: response.data.private,
      defaultBranch: response.data.default_branch,
      archived: response.data.archived,
    };
  }

  async archiveRepo(owner: string, repo: string): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('PATCH /repos/{owner}/{repo}', {
      owner,
      repo,
      archived: true,
    });
  }

  async deleteRepo(owner: string, repo: string): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('DELETE /repos/{owner}/{repo}', {
      owner,
      repo,
    });
  }

  // ========== Branch Operations ==========

  async listBranches(owner: string, repo: string): Promise<BranchInfo[]> {
    const octokit = this.ensureAuth();
    const branches: BranchInfo[] = [];

    const { data } = await octokit.request('GET /repos/{owner}/{repo}/branches', {
      owner,
      repo,
      per_page: 100,
    });

    for (const branch of data) {
      // Get commit details
      const { data: commit } = await octokit.request(
        'GET /repos/{owner}/{repo}/commits/{ref}',
        {
          owner,
          repo,
          ref: branch.commit.sha,
        }
      );

      branches.push({
        name: branch.name,
        protected: branch.protected,
        lastCommit: branch.commit.sha,
        lastCommitDate: new Date(commit.commit.committer?.date || Date.now()),
        merged: false, // Would need PR check
      });
    }

    return branches;
  }

  async deleteBranch(owner: string, repo: string, branch: string): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('DELETE /repos/{owner}/{repo}/git/refs/heads/{branch}', {
      owner,
      repo,
      branch,
    });
  }

  async protectBranch(
    owner: string,
    repo: string,
    branch: string,
    options: {
      requiredReviews?: number;
      dismissStaleReviews?: boolean;
      requireCodeOwnerReviews?: boolean;
      requireStatusChecks?: string[];
    }
  ): Promise<void> {
    const octokit = this.ensureAuth();

    await octokit.request(
      'PUT /repos/{owner}/{repo}/branches/{branch}/protection',
      {
        owner,
        repo,
        branch,
        required_status_checks: options.requireStatusChecks
          ? {
              strict: true,
              contexts: options.requireStatusChecks,
            }
          : null,
        enforce_admins: true,
        required_pull_request_reviews: options.requiredReviews
          ? {
              dismiss_stale_reviews: options.dismissStaleReviews ?? true,
              require_code_owner_reviews: options.requireCodeOwnerReviews ?? false,
              required_approving_review_count: options.requiredReviews,
            }
          : null,
        restrictions: null,
      }
    );
  }

  // ========== Security Operations ==========

  async getSecurityAlerts(
    owner: string,
    repo: string
  ): Promise<
    Array<{
      id: number;
      state: string;
      severity: string;
      package: string;
      title: string;
    }>
  > {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      {
        owner,
        repo,
        state: 'open',
      }
    );

    return data.map((alert: any) => ({
      id: alert.number,
      state: alert.state,
      severity: alert.security_advisory?.severity || 'unknown',
      package: alert.dependency?.package?.name || 'unknown',
      title: alert.security_advisory?.summary || 'Unknown vulnerability',
    }));
  }

  async dismissSecurityAlert(
    owner: string,
    repo: string,
    alertId: number,
    reason: 'fix_started' | 'inaccurate' | 'no_bandwidth' | 'not_used' | 'tolerable_risk'
  ): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request(
      'PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}',
      {
        owner,
        repo,
        alert_number: alertId,
        state: 'dismissed',
        dismissed_reason: reason,
      }
    );
  }

  // ========== State Repo Operations ==========

  async getFileContent(
    owner: string,
    repo: string,
    path: string
  ): Promise<{ content: string; sha: string }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/contents/{path}',
      {
        owner,
        repo,
        path,
      }
    );

    if (Array.isArray(data) || data.type !== 'file') {
      throw new Error(`${path} is not a file`);
    }

    return {
      content: Buffer.from(data.content, 'base64').toString('utf-8'),
      sha: data.sha,
    };
  }

  async updateFileContent(
    owner: string,
    repo: string,
    path: string,
    content: string,
    message: string,
    sha?: string
  ): Promise<void> {
    const octokit = this.ensureAuth();

    // Get current SHA if not provided
    if (!sha) {
      try {
        const current = await this.getFileContent(owner, repo, path);
        sha = current.sha;
      } catch {
        // File doesn't exist, will create
      }
    }

    await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
      owner,
      repo,
      path,
      message,
      content: Buffer.from(content).toString('base64'),
      sha,
    });
  }
}
