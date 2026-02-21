/**
 * git-fabric adapter
 *
 * Maps git-steer's GitHubClient + StateManager to the adapter
 * interfaces expected by @git-fabric/cve.
 *
 * This is the bridge between git-steer (the daily driver) and
 * git-fabric apps (composable layers).
 */

import type { GitHubClient } from '../github/client.js';
import type { StateManager } from '../state/manager.js';

// ── Adapter interfaces (mirrors @git-fabric/cve types) ─────────────────────
// Defined inline to avoid requiring @git-fabric/cve as a dependency.
// git-steer stays zero-footprint — no node_modules, no npm install.
// When fabric apps ship as packages, these can be imported directly.

export interface FabricGitHubAdapter {
  token: string;
  getFileContent(owner: string, repo: string, path: string): Promise<string | null>;
  createBranch(owner: string, repo: string, branch: string, fromBranch: string): Promise<void>;
  commitFiles(owner: string, repo: string, opts: {
    branch: string;
    message: string;
    files: { path: string; content: string }[];
  }): Promise<{ sha: string; url: string }>;
  createPullRequest(owner: string, repo: string, opts: {
    title: string;
    body: string;
    head: string;
    base: string;
    draft: boolean;
    labels: string[];
  }): Promise<{ number: number; html_url: string }>;
  getDefaultBranch(owner: string, repo: string): Promise<string>;
}

export interface FabricStateAdapter {
  read(file: string): Promise<string | null>;
  write(file: string, content: string): Promise<void>;
  append(file: string, lines: string[]): Promise<void>;
}

// ── Create GitHub adapter from git-steer's client ───────────────────────────

export function createGitHubAdapter(github: GitHubClient): FabricGitHubAdapter {
  return {
    // Token isn't directly exposed by GitHubClient, but GHSA queries
    // go through the client's authenticated Octokit instance anyway.
    // For fabric's detection layer (which needs a raw token for GraphQL),
    // we pass it through. In CI, it comes from env.
    token: process.env.GITHUB_TOKEN ?? process.env.GIT_STEER_TOKEN ?? '',

    async getFileContent(owner, repo, path) {
      try {
        const result = await github.getFile(owner, repo, path);
        return result?.content ?? null;
      } catch {
        return null;
      }
    },

    async createBranch(owner, repo, branch, fromBranch) {
      await github.createBranch(owner, repo, branch, fromBranch);
    },

    async commitFiles(owner, repo, opts) {
      return github.commitFiles(owner, repo, {
        branch: opts.branch,
        message: opts.message,
        files: opts.files,
      });
    },

    async createPullRequest(owner, repo, opts) {
      // Ensure labels exist before creating PR
      for (const label of opts.labels) {
        try {
          const color = label.startsWith('severity:critical') ? 'B60205'
            : label.startsWith('severity:high') ? 'D93F0B'
            : label.startsWith('severity:medium') ? 'FBCA04'
            : label.startsWith('severity:low') ? '0E8A16'
            : label === 'git-fabric' ? '1f6feb'
            : '1D76DB';
          await github.ensureLabel(owner, repo, label, color, `git-fabric: ${label}`);
        } catch {
          // label ops are best-effort
        }
      }

      const result = await github.createPullRequest(owner, repo, {
        title: opts.title,
        body: opts.body,
        head: opts.head,
        base: opts.base,
        labels: opts.labels,
      });

      return { number: result.number, html_url: result.url };
    },

    async getDefaultBranch(owner, repo) {
      const branches = await github.listBranches(owner, repo);
      const main = branches.find((b) => b.name === 'main');
      return main?.name ?? branches[0]?.name ?? 'main';
    },
  };
}

// ── Create state adapter from git-steer's state manager ─────────────────────

export function createStateAdapter(
  github: GitHubClient,
  stateRepo: string,
): FabricStateAdapter {
  const [stateOwner, stateRepoName] = stateRepo.includes('/')
    ? stateRepo.split('/')
    : ['ry-ops', stateRepo];

  return {
    async read(file) {
      try {
        const result = await github.getFile(stateOwner, stateRepoName, file);
        return result?.content ?? null;
      } catch {
        return null;
      }
    },

    async write(file, content) {
      let sha: string | undefined;
      try {
        const existing = await github.getFileContent(stateOwner, stateRepoName, file);
        sha = existing?.sha;
      } catch {
        // file doesn't exist yet
      }

      await github.updateFileContent(
        stateOwner,
        stateRepoName,
        file,
        content,
        `chore(cve): update ${file}`,
        sha ?? '',
      );
    },

    async append(file, lines) {
      const existing = await this.read(file);
      const newContent = existing
        ? existing + '\n' + lines.join('\n')
        : lines.join('\n');
      await this.write(file, newContent);
    },
  };
}
