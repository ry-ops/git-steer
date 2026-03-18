/**
 * @git-fabric/git inline connector
 *
 * Thin wrappers around the GitHubAdapter for git and repository operations.
 * Mirrors the @git-fabric/git FabricApp layer API so git-steer can delegate
 * repo/branch/PR/commit operations without requiring the package as a dependency.
 *
 * When @git-fabric/git is published to npm, these can be replaced with
 * direct imports. Until then this connector provides the same interface inline.
 */

import type { FabricGitHubAdapter } from './adapter.js';

// ── Repos ────────────────────────────────────────────────────────────────────

export async function listRepos(
  github: FabricGitHubAdapter,
  org?: string,
): Promise<{ owner: string; name: string; fullName: string; private: boolean; defaultBranch: string; url: string; pushedAt?: string }[]> {
  // Delegate via octokit token — direct REST call
  const headers = github.headers();
  const url = org
    ? `https://api.github.com/orgs/${encodeURIComponent(org)}/repos?per_page=100&sort=pushed`
    : `https://api.github.com/user/repos?per_page=100&sort=pushed`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`listRepos: ${res.status} ${await res.text()}`);
  const data = await res.json() as any[];
  return data.map((r) => ({
    owner: r.owner?.login ?? '',
    name: r.name,
    fullName: r.full_name,
    private: r.private,
    defaultBranch: r.default_branch ?? 'main',
    url: r.html_url ?? '',
    pushedAt: r.pushed_at ?? undefined,
  }));
}

// ── Files ─────────────────────────────────────────────────────────────────────

export async function getFileContent(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  path: string,
  ref?: string,
): Promise<string | null> {
  return github.getFileContent(owner, repo, path);
}

export async function listFiles(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  path = '',
  ref?: string,
): Promise<{ path: string; type: string; size?: number; sha: string }[]> {
  const headers = github.headers();
  const q = ref ? `?ref=${encodeURIComponent(ref)}` : '';
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}${q}`;
  const res = await fetch(url, { headers });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`listFiles: ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data)) return [];
  return data.map((f: any) => ({ path: f.path, type: f.type, size: f.size, sha: f.sha ?? '' }));
}

// ── Commits ───────────────────────────────────────────────────────────────────

export async function commitFiles(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  opts: {
    branch: string;
    message: string;
    files: { path: string; content: string }[];
    createBranch?: boolean;
    fromBranch?: string;
  },
): Promise<{ sha: string; url: string; branch: string }> {
  const result = await github.commitFiles(owner, repo, {
    branch: opts.branch,
    message: opts.message,
    files: opts.files,
  });
  return { ...result, branch: opts.branch };
}

export async function listCommits(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  branch?: string,
  limit = 20,
): Promise<{ sha: string; shortSha: string; message: string; author: string; date: string; url: string }[]> {
  const headers = github.headers();
  const q = new URLSearchParams({ per_page: String(limit) });
  if (branch) q.set('sha', branch);
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits?${q}`, { headers });
  if (!res.ok) throw new Error(`listCommits: ${res.status}`);
  const data = await res.json() as any[];
  return data.map((c) => ({
    sha: c.sha,
    shortSha: c.sha.slice(0, 8),
    message: (c.commit.message ?? '').split('\n')[0],
    author: c.commit.author?.name ?? c.author?.login ?? '',
    date: c.commit.author?.date ?? '',
    url: c.html_url,
  }));
}

export async function getCommit(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  sha: string,
): Promise<{ sha: string; shortSha: string; message: string; author: string; date: string; additions: number; deletions: number; files: { filename: string; status: string; additions: number; deletions: number }[] }> {
  const headers = github.headers();
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${sha}`, { headers });
  if (!res.ok) throw new Error(`getCommit: ${res.status}`);
  const c = await res.json() as any;
  return {
    sha: c.sha,
    shortSha: c.sha.slice(0, 8),
    message: (c.commit.message ?? '').split('\n')[0],
    author: c.commit.author?.name ?? c.author?.login ?? '',
    date: c.commit.author?.date ?? '',
    additions: c.stats?.additions ?? 0,
    deletions: c.stats?.deletions ?? 0,
    files: (c.files ?? []).map((f: any) => ({
      filename: f.filename,
      status: f.status,
      additions: f.additions,
      deletions: f.deletions,
    })),
  };
}

export async function compareCommits(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  base: string,
  head: string,
): Promise<{ status: string; aheadBy: number; behindBy: number; commits: { sha: string; message: string }[]; files: { filename: string; status: string }[] }> {
  const headers = github.headers();
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`,
    { headers },
  );
  if (!res.ok) throw new Error(`compareCommits: ${res.status}`);
  const d = await res.json() as any;
  return {
    status: d.status,
    aheadBy: d.ahead_by,
    behindBy: d.behind_by,
    commits: (d.commits ?? []).map((c: any) => ({ sha: c.sha, message: (c.commit.message ?? '').split('\n')[0] })),
    files: (d.files ?? []).map((f: any) => ({ filename: f.filename, status: f.status })),
  };
}

// ── Branches ──────────────────────────────────────────────────────────────────

export async function listBranches(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
): Promise<{ name: string; sha: string; protected: boolean }[]> {
  const headers = github.headers();
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/branches?per_page=100`, { headers });
  if (!res.ok) throw new Error(`listBranches: ${res.status}`);
  const data = await res.json() as any[];
  return data.map((b) => ({ name: b.name, sha: b.commit.sha, protected: b.protected }));
}

export async function createBranch(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  branch: string,
  fromBranch: string,
): Promise<{ owner: string; repo: string; branch: string; from: string }> {
  await github.createBranch(owner, repo, branch, fromBranch);
  return { owner, repo, branch, from: fromBranch };
}

export async function deleteBranch(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  branch: string,
): Promise<{ owner: string; repo: string; branch: string; deleted: true }> {
  const headers = github.headers();
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`, { method: 'DELETE', headers });
  if (!res.ok && res.status !== 422) throw new Error(`deleteBranch: ${res.status}`);
  return { owner, repo, branch, deleted: true };
}

// ── Pull Requests ─────────────────────────────────────────────────────────────

export async function listPullRequests(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  state: 'open' | 'closed' | 'all' = 'open',
): Promise<{ number: number; title: string; state: string; author: string; head: string; base: string; url: string; draft: boolean }[]> {
  const headers = github.headers();
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls?state=${state}&per_page=50`, { headers });
  if (!res.ok) throw new Error(`listPullRequests: ${res.status}`);
  const data = await res.json() as any[];
  return data.map((pr) => ({
    number: pr.number,
    title: pr.title,
    state: pr.merged_at ? 'merged' : pr.state,
    author: pr.user?.login ?? '',
    head: pr.head.ref,
    base: pr.base.ref,
    url: pr.html_url,
    draft: pr.draft ?? false,
  }));
}

export async function getPullRequest(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  number: number,
): Promise<{ number: number; title: string; state: string; body: string; author: string; head: string; base: string; url: string; draft: boolean; labels: string[]; additions: number; deletions: number; changedFiles: number }> {
  const headers = github.headers();
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${number}`, { headers });
  if (!res.ok) throw new Error(`getPullRequest: ${res.status}`);
  const pr = await res.json() as any;
  return {
    number: pr.number, title: pr.title,
    state: pr.merged_at ? 'merged' : pr.state,
    body: pr.body ?? '',
    author: pr.user?.login ?? '',
    head: pr.head.ref, base: pr.base.ref,
    url: pr.html_url, draft: pr.draft ?? false,
    labels: (pr.labels ?? []).map((l: any) => l.name),
    additions: pr.additions, deletions: pr.deletions,
    changedFiles: pr.changed_files,
  };
}

export async function createPullRequest(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  opts: { title: string; head: string; base: string; body?: string; draft?: boolean; labels?: string[] },
): Promise<{ number: number; url: string; state: string; draft: boolean }> {
  const result = await github.createPullRequest(owner, repo, {
    title: opts.title,
    body: opts.body ?? '',
    head: opts.head,
    base: opts.base,
    draft: opts.draft ?? false,
    labels: opts.labels ?? [],
  });
  return { number: result.number, url: result.html_url, state: 'open', draft: opts.draft ?? false };
}

export async function mergePullRequest(
  github: FabricGitHubAdapter,
  owner: string,
  repo: string,
  number: number,
  method: 'merge' | 'squash' | 'rebase' = 'squash',
  commitTitle?: string,
): Promise<{ merged: boolean; sha?: string; message: string }> {
  const headers = github.headers();
  const body: Record<string, string> = { merge_method: method };
  if (commitTitle) body.commit_title = commitTitle;
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${number}/merge`, {
    method: 'PUT',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`mergePullRequest: ${res.status} ${await res.text()}`);
  const d = await res.json() as any;
  return { merged: d.merged ?? true, sha: d.sha, message: d.message ?? 'Merged' };
}
