/**
 * FabricGitHubAdapter — minimal interface used by the git.ts connector.
 * Provides auth headers and key GitHub operations needed by fabric/git.ts.
 */
export interface FabricGitHubAdapter {
  /** Returns pre-built Authorization headers. Raw token is never exposed. */
  headers(): Record<string, string>;

  getFileContent(owner: string, repo: string, path: string): Promise<string | null>;

  commitFiles(
    owner: string,
    repo: string,
    opts: {
      branch: string;
      message: string;
      files: { path: string; content: string }[];
      createBranch?: boolean;
      baseBranch?: string;
    },
  ): Promise<{ sha: string; url: string }>;

  createBranch(owner: string, repo: string, branch: string, fromBranch: string): Promise<void>;

  createPullRequest(
    owner: string,
    repo: string,
    opts: {
      title: string;
      body: string;
      head: string;
      base: string;
      draft?: boolean;
      labels?: string[];
    },
  ): Promise<{ number: number; html_url: string; url: string }>;
}
