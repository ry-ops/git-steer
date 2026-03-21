/**
 * Lightweight GitHub client using token auth only.
 * No Keychain, no App auth, no keytar dependency.
 * Used by the web server entry point.
 */

import { Octokit } from 'octokit';

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
