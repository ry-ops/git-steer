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
    this.installationId = parseInt(config.installationId, 10);
    if (isNaN(this.installationId) || this.installationId <= 0) {
      throw new Error(
        `Invalid installation ID: "${config.installationId}". Must be a positive number.`
      );
    }
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

    // Use pagination to get all branches
    for await (const response of octokit.paginate.iterator(
      'GET /repos/{owner}/{repo}/branches',
      { owner, repo, per_page: 100 }
    )) {
      for (const branch of response.data) {
        // Use commit date from branch data to avoid N+1 API calls
        // The branch endpoint includes commit info
        branches.push({
          name: branch.name,
          protected: branch.protected,
          lastCommit: branch.commit.sha,
          lastCommitDate: new Date(), // Will be updated if we need accurate dates
          merged: false, // Would need PR check
        });
      }
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

  // ========== Pull Request Operations ==========

  async getPullRequest(
    owner: string,
    repo: string,
    pullNumber: number
  ): Promise<{
    number: number;
    state: string;
    merged: boolean;
    mergedAt: string | null;
    mergeable: boolean | null;
    labels: string[];
    updatedAt: string;
    createdAt: string;
    htmlUrl: string;
  }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', {
      owner,
      repo,
      pull_number: pullNumber,
    });

    return {
      number: data.number,
      state: data.state,
      merged: data.merged,
      mergedAt: data.merged_at,
      mergeable: data.mergeable,
      labels: data.labels.map((l: any) => (typeof l === 'string' ? l : l.name)),
      updatedAt: data.updated_at,
      createdAt: data.created_at,
      htmlUrl: data.html_url,
    };
  }

  // ========== Vulnerability Alerts Management ==========

  async enableVulnerabilityAlerts(owner: string, repo: string): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('PUT /repos/{owner}/{repo}/vulnerability-alerts', {
      owner,
      repo,
    });
  }

  async enableAutomatedSecurityFixes(owner: string, repo: string): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('PUT /repos/{owner}/{repo}/automated-security-fixes', {
      owner,
      repo,
    });
  }

  async checkVulnerabilityAlertsEnabled(owner: string, repo: string): Promise<boolean> {
    const octokit = this.ensureAuth();
    try {
      await octokit.request('GET /repos/{owner}/{repo}/vulnerability-alerts', {
        owner,
        repo,
      });
      return true; // 204 = enabled
    } catch (error: any) {
      if (error.status === 404) {
        return false; // 404 = disabled
      }
      throw error;
    }
  }

  // ========== Repository Settings ==========

  async updateRepoSettings(
    owner: string,
    repo: string,
    settings: {
      description?: string;
      homepage?: string;
      private?: boolean;
      has_issues?: boolean;
      has_projects?: boolean;
      has_wiki?: boolean;
      default_branch?: string;
    }
  ): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('PATCH /repos/{owner}/{repo}', {
      owner,
      repo,
      ...settings,
    });
  }

  // ========== Actions Operations ==========

  async listWorkflows(
    owner: string,
    repo: string
  ): Promise<Array<{ id: number; name: string; path: string; state: string }>> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/actions/workflows', {
      owner,
      repo,
    });

    return data.workflows.map((w: any) => ({
      id: w.id,
      name: w.name,
      path: w.path,
      state: w.state,
    }));
  }

  async triggerWorkflow(
    owner: string,
    repo: string,
    workflowId: string | number,
    ref: string,
    inputs?: Record<string, string>
  ): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request(
      'POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches',
      {
        owner,
        repo,
        workflow_id: workflowId,
        ref,
        inputs,
      }
    );
  }

  async listSecrets(
    owner: string,
    repo: string
  ): Promise<Array<{ name: string; created_at: string; updated_at: string }>> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/actions/secrets', {
      owner,
      repo,
    });

    return data.secrets.map((s: any) => ({
      name: s.name,
      created_at: s.created_at,
      updated_at: s.updated_at,
    }));
  }

  async setSecret(owner: string, repo: string, name: string, value: string): Promise<void> {
    const octokit = this.ensureAuth();

    // Get the public key for encrypting secrets
    const { data: keyData } = await octokit.request(
      'GET /repos/{owner}/{repo}/actions/secrets/public-key',
      { owner, repo }
    );

    // Use libsodium-wrappers for encryption (optional dependency)
    let sodium: {
      ready: Promise<void>;
      from_base64: (input: string, variant: number) => Uint8Array;
      from_string: (input: string) => Uint8Array;
      crypto_box_seal: (message: Uint8Array, publicKey: Uint8Array) => Uint8Array;
      to_base64: (input: Uint8Array, variant: number) => string;
      base64_variants: { ORIGINAL: number };
    };

    try {
      // Dynamic import to make it optional
      const libsodium = await (Function('return import("libsodium-wrappers")')() as Promise<any>);
      sodium = libsodium.default || libsodium;
      await sodium.ready;
    } catch {
      throw new Error(
        'libsodium-wrappers is required for setting secrets. Install with: npm install libsodium-wrappers'
      );
    }

    const binKey = sodium.from_base64(keyData.key, sodium.base64_variants.ORIGINAL);
    const binValue = sodium.from_string(value);
    const encryptedBytes = sodium.crypto_box_seal(binValue, binKey);
    const encrypted = sodium.to_base64(encryptedBytes, sodium.base64_variants.ORIGINAL);

    await octokit.request('PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}', {
      owner,
      repo,
      secret_name: name,
      encrypted_value: encrypted,
      key_id: keyData.key_id,
    });
  }

  async deleteSecret(owner: string, repo: string, name: string): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}', {
      owner,
      repo,
      secret_name: name,
    });
  }

  // ========== Workflow Dispatch Operations ==========

  /**
   * Dispatch a workflow in the git-steer repo to perform work on a target repo
   */
  async dispatchSecurityFix(
    targetRepo: string,
    options: {
      severity?: 'critical' | 'high' | 'medium' | 'low' | 'all';
      dryRun?: boolean;
      jobId?: string;
    }
  ): Promise<{ dispatched: boolean; jobId: string; workflowRun?: string }> {
    const octokit = this.ensureAuth();
    const jobId = options.jobId || `security-fix-${Date.now()}`;

    await octokit.request(
      'POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches',
      {
        owner: 'ry-ops',
        repo: 'git-steer',
        workflow_id: 'security-fix.yml',
        ref: 'main',
        inputs: {
          target_repo: targetRepo,
          severity: options.severity || 'critical',
          dry_run: String(options.dryRun || false),
          job_id: jobId,
        },
      }
    );

    return {
      dispatched: true,
      jobId,
    };
  }

  /**
   * Get recent workflow runs for a workflow
   */
  async getWorkflowRuns(
    owner: string,
    repo: string,
    workflowId: string,
    options?: { status?: string; perPage?: number }
  ): Promise<
    Array<{
      id: number;
      status: string;
      conclusion: string | null;
      createdAt: string;
      updatedAt: string;
      htmlUrl: string;
    }>
  > {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs',
      {
        owner,
        repo,
        workflow_id: workflowId,
        status: options?.status as any,
        per_page: options?.perPage || 10,
      }
    );

    return data.workflow_runs.map((run: any) => ({
      id: run.id,
      status: run.status,
      conclusion: run.conclusion,
      createdAt: run.created_at,
      updatedAt: run.updated_at,
      htmlUrl: run.html_url,
    }));
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

  // ========== Security Operations (Extended) ==========

  async getSecurityAlertsDetailed(
    owner: string,
    repo: string
  ): Promise<
    Array<{
      id: number;
      state: string;
      severity: string;
      package: string;
      currentVersion: string;
      fixVersion: string | null;
      cve: string | null;
      summary: string;
      manifestPath: string;
      url: string;
    }>
  > {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      { owner, repo, state: 'open' }
    );

    return data.map((alert: any) => ({
      id: alert.number,
      state: alert.state,
      severity: alert.security_advisory?.severity || 'unknown',
      package: alert.dependency?.package?.name || 'unknown',
      currentVersion: alert.security_vulnerability?.vulnerable_version_range || 'unknown',
      fixVersion: alert.security_vulnerability?.first_patched_version?.identifier || null,
      cve: alert.security_advisory?.cve_id || null,
      summary: alert.security_advisory?.summary || 'Unknown vulnerability',
      manifestPath: alert.dependency?.manifest_path || 'unknown',
      url: alert.html_url,
    }));
  }

  async createBranch(
    owner: string,
    repo: string,
    branchName: string,
    fromBranch?: string
  ): Promise<void> {
    const octokit = this.ensureAuth();

    // Get the SHA of the source branch
    const sourceBranch = fromBranch || 'main';
    const { data: ref } = await octokit.request(
      'GET /repos/{owner}/{repo}/git/ref/heads/{branch}',
      { owner, repo, branch: sourceBranch }
    );

    // Create new branch
    await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
      owner,
      repo,
      ref: `refs/heads/${branchName}`,
      sha: ref.object.sha,
    });
  }

  async createPullRequest(
    owner: string,
    repo: string,
    options: {
      title: string;
      body: string;
      head: string;
      base?: string;
      labels?: string[];
    }
  ): Promise<{ number: number; url: string }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
      owner,
      repo,
      title: options.title,
      body: options.body,
      head: options.head,
      base: options.base || 'main',
    });

    // GitHub's PR create API doesn't support labels, so apply them after creation
    if (options.labels && options.labels.length > 0) {
      await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/labels', {
        owner,
        repo,
        issue_number: data.number,
        labels: options.labels,
      });
    }

    return { number: data.number, url: data.html_url };
  }

  async commitFile(
    owner: string,
    repo: string,
    branch: string,
    path: string,
    content: string,
    message: string
  ): Promise<void> {
    const octokit = this.ensureAuth();

    // Get current file SHA if it exists
    let sha: string | undefined;
    try {
      const { data } = await octokit.request(
        'GET /repos/{owner}/{repo}/contents/{path}',
        { owner, repo, path, ref: branch }
      );
      if (!Array.isArray(data)) {
        sha = data.sha;
      }
    } catch {
      // File doesn't exist
    }

    await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
      owner,
      repo,
      path,
      message,
      content: Buffer.from(content).toString('base64'),
      branch,
      sha,
    });
  }

  // ========== Multi-File Commit Operations ==========

  /**
   * Commit multiple files in a single commit using the Git Data API.
   * This is more efficient than multiple single-file commits and creates
   * a cleaner git history.
   */
  async commitFiles(
    owner: string,
    repo: string,
    options: {
      branch: string;
      message: string;
      files: Array<{
        path: string;
        content: string;
        /** Set to true to delete this file */
        delete?: boolean;
      }>;
      /** Create branch if it doesn't exist */
      createBranch?: boolean;
      /** Base branch for new branch creation */
      baseBranch?: string;
    }
  ): Promise<{ sha: string; url: string }> {
    const octokit = this.ensureAuth();

    // Get the reference for the branch (or base branch if creating new)
    let baseSha: string;
    let branchExists = true;

    try {
      const { data: ref } = await octokit.request(
        'GET /repos/{owner}/{repo}/git/ref/heads/{branch}',
        { owner, repo, branch: options.branch }
      );
      baseSha = ref.object.sha;
    } catch (error: any) {
      if (error.status === 404 && options.createBranch) {
        // Branch doesn't exist, get base branch SHA
        const baseBranch = options.baseBranch || 'main';
        const { data: ref } = await octokit.request(
          'GET /repos/{owner}/{repo}/git/ref/heads/{branch}',
          { owner, repo, branch: baseBranch }
        );
        baseSha = ref.object.sha;
        branchExists = false;
      } else {
        throw error;
      }
    }

    // Get the current commit to find the base tree
    const { data: baseCommit } = await octokit.request(
      'GET /repos/{owner}/{repo}/git/commits/{commit_sha}',
      { owner, repo, commit_sha: baseSha }
    );

    // Create blobs for each file and build tree entries
    const treeEntries: Array<{
      path: string;
      mode: '100644' | '100755' | '040000' | '160000' | '120000';
      type: 'blob' | 'tree' | 'commit';
      sha?: string | null;
    }> = [];

    for (const file of options.files) {
      if (file.delete) {
        // To delete, set sha to null
        treeEntries.push({
          path: file.path,
          mode: '100644',
          type: 'blob',
          sha: null,
        });
      } else {
        // Create blob for file content
        const { data: blob } = await octokit.request(
          'POST /repos/{owner}/{repo}/git/blobs',
          {
            owner,
            repo,
            content: Buffer.from(file.content).toString('base64'),
            encoding: 'base64',
          }
        );

        treeEntries.push({
          path: file.path,
          mode: '100644',
          type: 'blob',
          sha: blob.sha,
        });
      }
    }

    // Create new tree
    const { data: newTree } = await octokit.request(
      'POST /repos/{owner}/{repo}/git/trees',
      {
        owner,
        repo,
        base_tree: baseCommit.tree.sha,
        tree: treeEntries,
      }
    );

    // Create commit
    const { data: newCommit } = await octokit.request(
      'POST /repos/{owner}/{repo}/git/commits',
      {
        owner,
        repo,
        message: options.message,
        tree: newTree.sha,
        parents: [baseSha],
      }
    );

    // Update or create branch reference
    if (branchExists) {
      await octokit.request('PATCH /repos/{owner}/{repo}/git/refs/heads/{branch}', {
        owner,
        repo,
        branch: options.branch,
        sha: newCommit.sha,
      });
    } else {
      await octokit.request('POST /repos/{owner}/{repo}/git/refs', {
        owner,
        repo,
        ref: `refs/heads/${options.branch}`,
        sha: newCommit.sha,
      });
    }

    return {
      sha: newCommit.sha,
      url: newCommit.html_url,
    };
  }

  /**
   * Get file content from a repo
   */
  async getFile(
    owner: string,
    repo: string,
    path: string,
    ref?: string
  ): Promise<{ content: string; sha: string } | null> {
    const octokit = this.ensureAuth();

    try {
      const { data } = await octokit.request(
        'GET /repos/{owner}/{repo}/contents/{path}',
        { owner, repo, path, ref }
      );

      if (Array.isArray(data) || data.type !== 'file') {
        return null;
      }

      return {
        content: Buffer.from(data.content, 'base64').toString('utf-8'),
        sha: data.sha,
      };
    } catch (error: any) {
      if (error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  // ========== Issue Operations ==========

  async createIssue(
    owner: string,
    repo: string,
    options: {
      title: string;
      body: string;
      labels?: string[];
      assignees?: string[];
    }
  ): Promise<{ number: number; url: string; id: number }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('POST /repos/{owner}/{repo}/issues', {
      owner,
      repo,
      title: options.title,
      body: options.body,
      labels: options.labels,
      assignees: options.assignees,
    });

    return { number: data.number, url: data.html_url, id: data.id };
  }

  async updateIssue(
    owner: string,
    repo: string,
    issueNumber: number,
    updates: {
      state?: 'open' | 'closed';
      labels?: string[];
      state_reason?: 'completed' | 'not_planned' | 'reopened';
    }
  ): Promise<void> {
    const octokit = this.ensureAuth();
    await octokit.request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
      owner,
      repo,
      issue_number: issueNumber,
      state: updates.state,
      labels: updates.labels,
      state_reason: updates.state_reason,
    });
  }

  async addIssueComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string
  ): Promise<{ id: number; url: string }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request(
      'POST /repos/{owner}/{repo}/issues/{issue_number}/comments',
      { owner, repo, issue_number: issueNumber, body }
    );

    return { id: data.id, url: data.html_url };
  }

  async listIssues(
    owner: string,
    repo: string,
    options?: { state?: 'open' | 'closed' | 'all'; labels?: string; per_page?: number }
  ): Promise<
    Array<{
      number: number;
      title: string;
      state: string;
      labels: string[];
      url: string;
      createdAt: string;
    }>
  > {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/issues', {
      owner,
      repo,
      state: options?.state || 'open',
      labels: options?.labels,
      per_page: options?.per_page || 30,
    });

    return data.map((issue: any) => ({
      number: issue.number,
      title: issue.title,
      state: issue.state,
      labels: issue.labels.map((l: any) => (typeof l === 'string' ? l : l.name)),
      url: issue.html_url,
      createdAt: issue.created_at,
    }));
  }

  async ensureLabel(
    owner: string,
    repo: string,
    name: string,
    color: string,
    description: string
  ): Promise<void> {
    const octokit = this.ensureAuth();
    try {
      await octokit.request('PATCH /repos/{owner}/{repo}/labels/{name}', {
        owner,
        repo,
        name,
        color,
        description,
      });
    } catch (error: any) {
      if (error.status === 404) {
        await octokit.request('POST /repos/{owner}/{repo}/labels', {
          owner,
          repo,
          name,
          color,
          description,
        });
      } else {
        throw error;
      }
    }
  }

  // ========== Release Operations ==========

  async createDraftRelease(
    owner: string,
    repo: string,
    options: {
      tagName: string;
      name: string;
      body: string;
      prerelease?: boolean;
    }
  ): Promise<{ id: number; url: string; htmlUrl: string }> {
    const octokit = this.ensureAuth();
    const { data } = await octokit.request('POST /repos/{owner}/{repo}/releases', {
      owner,
      repo,
      tag_name: options.tagName,
      name: options.name,
      body: options.body,
      draft: true,
      prerelease: options.prerelease ?? false,
    });

    return { id: data.id, url: data.url, htmlUrl: data.html_url };
  }

  // ========== Code Scanning Operations ==========

  async getCodeScanningAlerts(
    owner: string,
    repo: string
  ): Promise<
    Array<{
      number: number;
      rule: { id: string; severity: string; description: string };
      tool: string;
      state: string;
      location: { path: string; startLine: number };
      url: string;
    }>
  > {
    const octokit = this.ensureAuth();
    try {
      const { data } = await octokit.request(
        'GET /repos/{owner}/{repo}/code-scanning/alerts',
        { owner, repo, state: 'open' }
      );

      return data.map((alert: any) => ({
        number: alert.number,
        rule: {
          id: alert.rule?.id || 'unknown',
          severity: alert.rule?.security_severity_level || alert.rule?.severity || 'unknown',
          description: alert.rule?.description || '',
        },
        tool: alert.tool?.name || 'unknown',
        state: alert.state,
        location: {
          path: alert.most_recent_instance?.location?.path || '',
          startLine: alert.most_recent_instance?.location?.start_line || 0,
        },
        url: alert.html_url,
      }));
    } catch (error: any) {
      // Code scanning may not be enabled for all repos
      if (error.status === 404 || error.status === 403) {
        return [];
      }
      throw error;
    }
  }

  /**
   * List files in a directory
   */
  async listFiles(
    owner: string,
    repo: string,
    path: string,
    ref?: string
  ): Promise<Array<{ name: string; path: string; type: 'file' | 'dir'; sha: string }>> {
    const octokit = this.ensureAuth();

    try {
      const { data } = await octokit.request(
        'GET /repos/{owner}/{repo}/contents/{path}',
        { owner, repo, path, ref }
      );

      if (!Array.isArray(data)) {
        return [];
      }

      return data.map((item: any) => ({
        name: item.name,
        path: item.path,
        type: item.type === 'dir' ? 'dir' : 'file',
        sha: item.sha,
      }));
    } catch (error: any) {
      if (error.status === 404) {
        return [];
      }
      throw error;
    }
  }
}
