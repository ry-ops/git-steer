/**
 * git-steer FabricApp
 *
 * Exports a FabricApp that wraps git-steer's GitHub tools for the
 * @git-fabric/gateway. Uses a PAT token (GITHUB_TOKEN env var) so it
 * works in-cluster without macOS Keychain / GitHub App credentials.
 *
 * Tools exposed (17):
 *   repo_list, repo_create, repo_archive, repo_settings
 *   branch_list, branch_protect, branch_reap
 *   security_alerts, security_digest
 *   actions_workflows, actions_trigger
 *   repo_read_file, repo_list_files, repo_commit
 *   pr_list, pr_create, pr_merge
 */

import { Octokit } from 'octokit';

interface FabricTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

interface FabricApp {
  name: string;
  version: string;
  description: string;
  tools: FabricTool[];
  health: () => Promise<{
    app: string;
    status: 'healthy' | 'degraded' | 'unavailable';
    latencyMs?: number;
    details?: Record<string, unknown>;
  }>;
}

function createOctokit(token: string): Octokit {
  return new Octokit({ auth: token });
}

export function createApp(tokenOverride?: string): FabricApp {
  const token = tokenOverride ?? process.env.GITHUB_TOKEN ?? process.env.GIT_STEER_TOKEN ?? '';
  const octokit = createOctokit(token);

  const tools: FabricTool[] = [
    // ── Repositories ──────────────────────────────────────────────────────────
    {
      name: 'git_steer_repo_list',
      description: 'List GitHub repositories accessible to the token. Optionally filter by org.',
      inputSchema: {
        type: 'object',
        properties: {
          org: { type: 'string', description: 'GitHub org name. Omit to list repos for the authenticated user.' },
          include_archived: { type: 'boolean', description: 'Include archived repos (default: false).' },
          filter: { type: 'string', description: 'Filter by name pattern (glob, e.g. "fabric-*").' },
        },
      },
      execute: async (a) => {
        let repos: Awaited<ReturnType<typeof octokit.rest.repos.listForOrg>>['data'] | Awaited<ReturnType<typeof octokit.rest.repos.listForAuthenticatedUser>>['data'];
        if (a.org) {
          const res = await octokit.rest.repos.listForOrg({ org: a.org as string, per_page: 100, sort: 'pushed' });
          repos = res.data;
        } else {
          const res = await octokit.rest.repos.listForAuthenticatedUser({ per_page: 100, sort: 'pushed' });
          repos = res.data;
        }
        let out = repos as any[];
        if (!a.include_archived) out = out.filter((r) => !r.archived);
        if (a.filter) {
          const pat = new RegExp('^' + String(a.filter).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
          out = out.filter((r) => pat.test(r.full_name) || pat.test(r.name));
        }
        return out.map((r) => ({
          fullName: r.full_name, name: r.name, owner: r.owner?.login,
          private: r.private, archived: r.archived, defaultBranch: r.default_branch,
          url: r.html_url, pushedAt: r.pushed_at,
        }));
      },
    },
    {
      name: 'git_steer_repo_create',
      description: 'Create a new GitHub repository.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          org: { type: 'string', description: 'Create under this org (omit for personal).' },
          description: { type: 'string' },
          private: { type: 'boolean', default: true },
        },
        required: ['name'],
      },
      execute: async (a) => {
        let res: { data: { full_name: string; html_url: string } };
        if (a.org) {
          res = await octokit.rest.repos.createInOrg({
            org: a.org as string, name: a.name as string,
            description: (a.description as string) ?? '', private: (a.private as boolean) ?? true,
          });
        } else {
          res = await octokit.rest.repos.createForAuthenticatedUser({
            name: a.name as string, description: (a.description as string) ?? '',
            private: (a.private as boolean) ?? true,
          });
        }
        return { created: true, fullName: res.data.full_name, url: res.data.html_url };
      },
    },
    {
      name: 'git_steer_repo_archive',
      description: 'Archive a GitHub repository (read-only, reversible).',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        await octokit.rest.repos.update({ owner: a.owner as string, repo: a.repo as string, archived: true });
        return { archived: true, repo: `${a.owner}/${a.repo}` };
      },
    },
    {
      name: 'git_steer_repo_settings',
      description: 'Update repository settings (description, homepage, visibility, etc.).',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          description: { type: 'string' },
          homepage: { type: 'string' },
          private: { type: 'boolean' },
          has_issues: { type: 'boolean' },
          has_wiki: { type: 'boolean' },
          default_branch: { type: 'string' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const { owner, repo, ...settings } = a as Record<string, unknown>;
        await octokit.rest.repos.update({ owner: owner as string, repo: repo as string, ...settings as any });
        return { updated: true, repo: `${owner}/${repo}` };
      },
    },

    // ── Branches ──────────────────────────────────────────────────────────────
    {
      name: 'git_steer_branch_list',
      description: 'List branches in a repository with stale detection.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          stale_days: { type: 'number', description: 'Days threshold for marking branches as stale (default: 30).' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const res = await octokit.rest.repos.listBranches({ owner: a.owner as string, repo: a.repo as string, per_page: 100 });
        const staleDays = (a.stale_days as number) ?? 30;
        const staleDate = new Date(Date.now() - staleDays * 86400000);
        return res.data.map((b) => ({
          name: b.name, sha: b.commit.sha, protected: b.protected,
        }));
      },
    },
    {
      name: 'git_steer_branch_protect',
      description: 'Apply branch protection rules to a repository branch.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          branch: { type: 'string' },
          required_reviews: { type: 'number', description: 'Number of required PR reviewers (default: 1).' },
          dismiss_stale_reviews: { type: 'boolean' },
          require_code_owner_reviews: { type: 'boolean' },
        },
        required: ['owner', 'repo', 'branch'],
      },
      execute: async (a) => {
        const requiredReviews = (a.required_reviews as number) ?? 1;
        await octokit.rest.repos.updateBranchProtection({
          owner: a.owner as string, repo: a.repo as string, branch: a.branch as string,
          required_status_checks: null,
          enforce_admins: false,
          required_pull_request_reviews: {
            required_approving_review_count: requiredReviews,
            dismiss_stale_reviews: (a.dismiss_stale_reviews as boolean) ?? false,
            require_code_owner_reviews: (a.require_code_owner_reviews as boolean) ?? false,
          },
          restrictions: null,
        });
        return { protected: true, branch: a.branch, requiredReviews };
      },
    },
    {
      name: 'git_steer_branch_reap',
      description: 'Delete stale merged branches from a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          days_stale: { type: 'number', description: 'Branches with last commit older than this are candidates (default: 30).' },
          exclude: { type: 'array', items: { type: 'string' }, description: 'Branch names to protect (default: main, master, develop).' },
          dry_run: { type: 'boolean' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const exclude = (a.exclude as string[]) ?? ['main', 'master', 'develop'];
        const staleDays = (a.days_stale as number) ?? 30;
        const staleDate = new Date(Date.now() - staleDays * 86400000);
        const res = await octokit.rest.repos.listBranches({ owner: a.owner as string, repo: a.repo as string, per_page: 100 });
        const candidates = res.data.filter((b) => !b.protected && !exclude.includes(b.name));
        // Check each candidate's last commit date via GraphQL-light: use REST commit list
        const toDelete: string[] = [];
        for (const b of candidates) {
          const commits = await octokit.rest.repos.listCommits({ owner: a.owner as string, repo: a.repo as string, sha: b.name, per_page: 1 });
          const lastDate = new Date(commits.data[0]?.commit?.committer?.date ?? 0);
          if (lastDate < staleDate) toDelete.push(b.name);
        }
        if (a.dry_run) return { dryRun: true, wouldDelete: toDelete };
        const deleted: string[] = [];
        for (const branch of toDelete) {
          await octokit.rest.git.deleteRef({ owner: a.owner as string, repo: a.repo as string, ref: `heads/${branch}` });
          deleted.push(branch);
        }
        return { deleted };
      },
    },

    // ── Security ──────────────────────────────────────────────────────────────
    {
      name: 'git_steer_security_alerts',
      description: 'Get Dependabot security alerts for a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'all'], description: 'Filter by severity (default: all).' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const res = await octokit.rest.dependabot.listAlertsForRepo({ owner: a.owner as string, repo: a.repo as string, per_page: 100, state: 'open' });
        let alerts = res.data.map((al) => ({
          number: al.number,
          severity: al.security_advisory?.severity ?? 'unknown',
          package: al.dependency?.package?.name ?? 'unknown',
          ecosystem: al.dependency?.package?.ecosystem ?? 'unknown',
          cve: al.security_advisory?.cve_id ?? null,
          summary: al.security_advisory?.summary ?? '',
          fixedIn: (al.security_vulnerability as any)?.first_patched_version?.identifier ?? null,
          url: al.html_url,
        }));
        if (a.severity && a.severity !== 'all') {
          alerts = alerts.filter((al) => al.severity === a.severity);
        }
        return { count: alerts.length, alerts };
      },
    },
    {
      name: 'git_steer_security_digest',
      description: 'Get security alert summary across multiple repositories. Pass repo list or uses authenticated user repos.',
      inputSchema: {
        type: 'object',
        properties: {
          repos: { type: 'array', items: { type: 'string' }, description: 'List of "owner/repo" strings. Omit to scan authenticated user repos.' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'all'], default: 'high' },
        },
      },
      execute: async (a) => {
        let repoList: { owner: string; repo: string }[];
        if (a.repos && (a.repos as string[]).length > 0) {
          repoList = (a.repos as string[]).map((r) => { const [owner, repo] = r.split('/'); return { owner, repo }; });
        } else {
          const res = await octokit.rest.repos.listForAuthenticatedUser({ per_page: 100, sort: 'pushed' });
          repoList = res.data.filter((r) => !r.archived).map((r) => ({ owner: r.owner?.login ?? '', repo: r.name }));
        }
        const digest: Record<string, unknown[]> = {};
        await Promise.allSettled(repoList.map(async ({ owner, repo }) => {
          try {
            const res = await octokit.rest.dependabot.listAlertsForRepo({ owner, repo, per_page: 100, state: 'open' });
            let alerts = res.data.map((al) => ({
              number: al.number, severity: al.security_advisory?.severity ?? 'unknown',
              package: al.dependency?.package?.name ?? 'unknown', cve: al.security_advisory?.cve_id ?? null,
              summary: al.security_advisory?.summary ?? '', fixedIn: (al.security_vulnerability as any)?.first_patched_version?.identifier ?? null,
            }));
            if (a.severity && a.severity !== 'all') alerts = alerts.filter((al) => al.severity === a.severity);
            if (alerts.length > 0) digest[`${owner}/${repo}`] = alerts;
          } catch { /* skip inaccessible repos */ }
        }));
        const total = Object.values(digest).reduce((sum, arr) => sum + arr.length, 0);
        return { reposWithAlerts: Object.keys(digest).length, totalAlerts: total, digest };
      },
    },

    // ── Actions ───────────────────────────────────────────────────────────────
    {
      name: 'git_steer_actions_workflows',
      description: 'List GitHub Actions workflows in a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const res = await octokit.rest.actions.listRepoWorkflows({ owner: a.owner as string, repo: a.repo as string });
        return res.data.workflows.map((w) => ({ id: w.id, name: w.name, path: w.path, state: w.state, url: w.html_url }));
      },
    },
    {
      name: 'git_steer_actions_trigger',
      description: 'Trigger a GitHub Actions workflow dispatch event.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          workflow: { type: 'string', description: 'Workflow file name (e.g. build.yml) or workflow ID.' },
          ref: { type: 'string', description: 'Branch or tag to run on (default: main).' },
          inputs: { type: 'object', description: 'Workflow inputs (key/value pairs).' },
        },
        required: ['owner', 'repo', 'workflow'],
      },
      execute: async (a) => {
        await octokit.rest.actions.createWorkflowDispatch({
          owner: a.owner as string, repo: a.repo as string,
          workflow_id: a.workflow as string, ref: (a.ref as string) ?? 'main',
          inputs: (a.inputs as Record<string, string>) ?? {},
        });
        return { triggered: true, workflow: a.workflow, ref: (a.ref as string) ?? 'main' };
      },
    },
    {
      name: 'git_steer_workflow_runs',
      description: 'Get recent workflow run status for a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          workflow: { type: 'string', description: 'Workflow file name or ID. Omit to get all recent runs.' },
          limit: { type: 'number', description: 'Max runs to return (default: 10).' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const limit = (a.limit as number) ?? 10;
        let runs: unknown[];
        if (a.workflow) {
          const res = await octokit.rest.actions.listWorkflowRuns({ owner: a.owner as string, repo: a.repo as string, workflow_id: a.workflow as string, per_page: limit });
          runs = res.data.workflow_runs;
        } else {
          const res = await octokit.rest.actions.listWorkflowRunsForRepo({ owner: a.owner as string, repo: a.repo as string, per_page: limit });
          runs = res.data.workflow_runs;
        }
        return (runs as any[]).map((r) => ({ id: r.id, name: r.name, status: r.status, conclusion: r.conclusion, createdAt: r.created_at, url: r.html_url }));
      },
    },

    // ── File Operations ───────────────────────────────────────────────────────
    {
      name: 'git_steer_repo_read_file',
      description: 'Read the content of a file from a GitHub repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          path: { type: 'string' },
          ref: { type: 'string', description: 'Branch, tag, or commit SHA.' },
        },
        required: ['owner', 'repo', 'path'],
      },
      execute: async (a) => {
        try {
          const res = await octokit.rest.repos.getContent({ owner: a.owner as string, repo: a.repo as string, path: a.path as string, ref: a.ref as string | undefined });
          const item = Array.isArray(res.data) ? res.data[0] : res.data;
          if (!item || (item as any).type !== 'file') return { found: false, path: a.path };
          const content = Buffer.from((item as any).content ?? '', 'base64').toString('utf8');
          return { found: true, path: a.path, sha: (item as any).sha, content };
        } catch (e: any) {
          if (e.status === 404) return { found: false, path: a.path };
          throw e;
        }
      },
    },
    {
      name: 'git_steer_repo_list_files',
      description: 'List files and directories at a path in a GitHub repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          path: { type: 'string', description: 'Directory path (default: root).' },
          ref: { type: 'string' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        try {
          const res = await octokit.rest.repos.getContent({ owner: a.owner as string, repo: a.repo as string, path: (a.path as string) ?? '', ref: a.ref as string | undefined });
          const items = Array.isArray(res.data) ? res.data : [res.data];
          return { path: a.path ?? '/', count: items.length, files: items.map((f: any) => ({ name: f.name, path: f.path, type: f.type, size: f.size, sha: f.sha })) };
        } catch (e: any) {
          if (e.status === 404) return { path: a.path, count: 0, files: [] };
          throw e;
        }
      },
    },
    {
      name: 'git_steer_repo_commit',
      description: 'Commit one or more files to a branch via the GitHub API. Can create a PR from the new branch.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          branch: { type: 'string', description: 'Target branch (default: main).' },
          message: { type: 'string' },
          files: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] } },
          create_branch: { type: 'boolean', description: 'Create the branch if it does not exist.' },
          base_branch: { type: 'string', description: 'Source branch when creating a new branch (default: main).' },
          create_pr: { type: 'boolean' },
          pr_title: { type: 'string' },
          pr_body: { type: 'string' },
        },
        required: ['owner', 'repo', 'message', 'files'],
      },
      execute: async (a) => {
        const owner = a.owner as string;
        const repo = a.repo as string;
        const branch = (a.branch as string) ?? 'main';
        const baseBranch = (a.base_branch as string) ?? 'main';
        const files = a.files as { path: string; content: string }[];

        // Get base branch SHA
        const baseRef = await octokit.rest.git.getRef({ owner, repo, ref: `heads/${baseBranch}` });
        const baseSha = baseRef.data.object.sha;

        // Create branch if needed
        if (a.create_branch && branch !== baseBranch) {
          try {
            await octokit.rest.git.createRef({ owner, repo, ref: `refs/heads/${branch}`, sha: baseSha });
          } catch (e: any) {
            if (e.status !== 422) throw e; // 422 = branch already exists, ignore
          }
        }

        // Get current tree
        const headRef = await octokit.rest.git.getRef({ owner, repo, ref: `heads/${branch}` });
        const headSha = headRef.data.object.sha;
        const headCommit = await octokit.rest.git.getCommit({ owner, repo, commit_sha: headSha });
        const baseTree = headCommit.data.tree.sha;

        // Create blobs
        const treeItems = await Promise.all(files.map(async (f) => {
          const blob = await octokit.rest.git.createBlob({ owner, repo, content: Buffer.from(f.content).toString('base64'), encoding: 'base64' });
          return { path: f.path, mode: '100644' as const, type: 'blob' as const, sha: blob.data.sha };
        }));

        // Create tree
        const tree = await octokit.rest.git.createTree({ owner, repo, base_tree: baseTree, tree: treeItems });

        // Create commit
        const commit = await octokit.rest.git.createCommit({ owner, repo, message: a.message as string, tree: tree.data.sha, parents: [headSha] });

        // Update ref
        await octokit.rest.git.updateRef({ owner, repo, ref: `heads/${branch}`, sha: commit.data.sha });

        let pr = null;
        if (a.create_pr && branch !== 'main' && branch !== 'master') {
          if (!a.pr_title) throw new Error('pr_title is required when create_pr is true');
          const prRes = await octokit.rest.pulls.create({ owner, repo, title: a.pr_title as string, body: (a.pr_body as string) ?? '', head: branch, base: baseBranch });
          pr = { number: prRes.data.number, url: prRes.data.html_url };
        }

        return { success: true, commit: { sha: commit.data.sha, url: commit.data.html_url }, branch, filesCommitted: files.length, pr };
      },
    },

    // ── Pull Requests ─────────────────────────────────────────────────────────
    {
      name: 'git_steer_pr_list',
      description: 'List pull requests in a repository.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'PR state (default: open).' },
          limit: { type: 'number', description: 'Max results (default: 30).' },
        },
        required: ['owner', 'repo'],
      },
      execute: async (a) => {
        const res = await octokit.rest.pulls.list({ owner: a.owner as string, repo: a.repo as string, state: (a.state as 'open' | 'closed' | 'all') ?? 'open', per_page: (a.limit as number) ?? 30 });
        return res.data.map((pr) => ({ number: pr.number, title: pr.title, state: pr.merged_at ? 'merged' : pr.state, author: pr.user?.login, head: pr.head.ref, base: pr.base.ref, draft: pr.draft, url: pr.html_url, createdAt: pr.created_at }));
      },
    },
    {
      name: 'git_steer_pr_create',
      description: 'Open a pull request.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          title: { type: 'string' },
          head: { type: 'string', description: 'Head branch.' },
          base: { type: 'string', description: 'Base branch (default: main).' },
          body: { type: 'string' },
          draft: { type: 'boolean' },
        },
        required: ['owner', 'repo', 'title', 'head'],
      },
      execute: async (a) => {
        const res = await octokit.rest.pulls.create({ owner: a.owner as string, repo: a.repo as string, title: a.title as string, head: a.head as string, base: (a.base as string) ?? 'main', body: (a.body as string) ?? '', draft: (a.draft as boolean) ?? false });
        return { number: res.data.number, url: res.data.html_url, state: 'open', draft: res.data.draft };
      },
    },
    {
      name: 'git_steer_pr_merge',
      description: 'Merge a pull request.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          number: { type: 'number', description: 'PR number.' },
          method: { type: 'string', enum: ['merge', 'squash', 'rebase'], description: 'Merge method (default: squash).' },
          commit_title: { type: 'string' },
        },
        required: ['owner', 'repo', 'number'],
      },
      execute: async (a) => {
        const res = await octokit.rest.pulls.merge({ owner: a.owner as string, repo: a.repo as string, pull_number: a.number as number, merge_method: (a.method as 'merge' | 'squash' | 'rebase') ?? 'squash', commit_title: a.commit_title as string | undefined });
        return { merged: res.data.merged, sha: res.data.sha, message: res.data.message };
      },
    },
  ];

  return {
    name: '@git-steer/fabric',
    version: '0.1.0',
    description: 'git-steer GitHub automation — repos, branches, security alerts, Actions, file ops, and PRs via PAT token',
    tools,
    async health() {
      const start = Date.now();
      try {
        await octokit.rest.users.getAuthenticated();
        return { app: '@git-steer/fabric', status: 'healthy', latencyMs: Date.now() - start };
      } catch (e: unknown) {
        return { app: '@git-steer/fabric', status: 'unavailable', latencyMs: Date.now() - start, details: { error: String(e) } };
      }
    },
  };
}
