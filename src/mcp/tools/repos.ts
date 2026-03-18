/**
 * Repository tools: repo_list, repo_create, repo_archive, repo_delete,
 * repo_settings, repo_commit, repo_read_file, repo_list_files
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDeps, ToolResult } from './types.js';

export function getTools(): Tool[] {
  return [
    {
      name: 'repo_list',
      description: 'List all repositories git-steer has access to',
      inputSchema: {
        type: 'object',
        properties: {
          filter: {
            type: 'string',
            description: 'Filter by name pattern (glob)',
          },
          includeArchived: {
            type: 'boolean',
            description: 'Include archived repos',
            default: false,
          },
        },
      },
    },
    {
      name: 'repo_create',
      description: 'Create a new repository',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Repository name' },
          description: { type: 'string', description: 'Repository description' },
          private: { type: 'boolean', description: 'Make repo private', default: true },
          template: {
            type: 'object',
            description: 'Create from template',
            properties: {
              owner: { type: 'string' },
              repo: { type: 'string' },
            },
          },
          addToManaged: {
            type: 'boolean',
            description: 'Add to managed repos with default policies',
            default: true,
          },
        },
        required: ['name'],
      },
    },
    {
      name: 'repo_archive',
      description: 'Archive a repository',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner' },
          repo: { type: 'string', description: 'Repository name' },
          confirm: { type: 'string', description: "Safety confirmation. Must be exactly 'CONFIRM_REPO_ARCHIVE' to proceed." },
        },
        required: ['owner', 'repo'],
      },
    },
    {
      name: 'repo_delete',
      description: 'Permanently delete a repository. Requires confirmation.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner' },
          repo: { type: 'string', description: 'Repository name' },
          confirm: {
            type: 'string',
            description: "Safety confirmation. Must be exactly 'CONFIRM_REPO_DELETE' to proceed.",
          },
        },
        required: ['owner', 'repo', 'confirm'],
      },
    },
    {
      name: 'repo_settings',
      description: 'Update repository settings',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          settings: {
            type: 'object',
            properties: {
              description: { type: 'string' },
              homepage: { type: 'string' },
              private: { type: 'boolean' },
              hasIssues: { type: 'boolean' },
              hasProjects: { type: 'boolean' },
              hasWiki: { type: 'boolean' },
              defaultBranch: { type: 'string' },
            },
          },
        },
        required: ['owner', 'repo', 'settings'],
      },
    },
    {
      name: 'repo_commit',
      description: 'Commit files directly to a repository via GitHub API (no local clone needed). Supports multiple files in a single commit.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner' },
          repo: { type: 'string', description: 'Repository name' },
          branch: { type: 'string', description: 'Branch to commit to', default: 'main' },
          message: { type: 'string', description: 'Commit message' },
          files: {
            type: 'array',
            description: 'Files to commit',
            items: {
              type: 'object',
              properties: {
                path: { type: 'string', description: 'File path in repo' },
                content: { type: 'string', description: 'File content' },
                delete: { type: 'boolean', description: 'Set true to delete file' },
              },
              required: ['path'],
            },
          },
          createBranch: {
            type: 'boolean',
            description: 'Create branch if it does not exist',
            default: false,
          },
          baseBranch: {
            type: 'string',
            description: 'Base branch for new branch creation',
            default: 'main',
          },
          createPr: {
            type: 'boolean',
            description: 'Create a pull request after committing',
            default: false,
          },
          prTitle: { type: 'string', description: 'PR title (required if createPr is true)' },
          prBody: { type: 'string', description: 'PR body/description' },
          prLabels: {
            type: 'array',
            items: { type: 'string' },
            description: 'Labels to apply to the PR',
          },
        },
        required: ['owner', 'repo', 'message', 'files'],
      },
    },
    {
      name: 'repo_read_file',
      description: 'Read a file from a repository',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          path: { type: 'string', description: 'File path in repo' },
          ref: { type: 'string', description: 'Branch, tag, or commit SHA', default: 'main' },
        },
        required: ['owner', 'repo', 'path'],
      },
    },
    {
      name: 'repo_list_files',
      description: 'List files in a repository directory',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string' },
          repo: { type: 'string' },
          path: { type: 'string', description: 'Directory path in repo', default: '' },
          ref: { type: 'string', description: 'Branch, tag, or commit SHA', default: 'main' },
        },
        required: ['owner', 'repo'],
      },
    },
    {
      name: 'repo_scrub_history',
      description: 'Purge sensitive files from all git history using git-filter-repo. Clones the repo as a mirror, removes specified paths from every commit, and force-pushes the rewritten history. DESTRUCTIVE: rewrites all commit SHAs.',
      inputSchema: {
        type: 'object',
        properties: {
          owner: { type: 'string', description: 'Repository owner or org' },
          repo: { type: 'string', description: 'Repository name' },
          paths: {
            type: 'array',
            items: { type: 'string' },
            description: 'File paths to purge from all history (e.g. [".env", "secrets/creds.yaml"])',
          },
          dryRun: { type: 'boolean', description: 'If true, report what would be purged without force-pushing. Default: false.', default: false },
          confirm: { type: 'string', description: "Safety confirmation. Must be exactly 'CONFIRM_REPO_SCRUB_HISTORY' to proceed." },
        },
        required: ['owner', 'repo', 'paths'],
      },
    },
  ];
}

export function handleCall(name: string, args: Record<string, any>, deps: ToolDeps): Promise<any> | null {
  switch (name) {
    case 'repo_list': return handleRepoList(args, deps);
    case 'repo_create': return handleRepoCreate(args, deps);
    case 'repo_archive': return handleRepoArchive(args, deps);
    case 'repo_delete': return handleRepoDelete(args, deps);
    case 'repo_settings': return handleRepoSettings(args, deps);
    case 'repo_commit': return handleRepoCommit(args, deps);
    case 'repo_read_file': return handleRepoReadFile(args, deps);
    case 'repo_list_files': return handleRepoListFiles(args, deps);
    case 'repo_scrub_history': return handleRepoScrubHistory(args, deps);
    default: return null;
  }
}

async function handleRepoList(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const repos = await deps.github.listRepos();
  let filtered = repos;

  if (!args.includeArchived) {
    filtered = filtered.filter((r) => !r.archived);
  }

  if (args.filter) {
    const escaped = args.filter
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    const pattern = new RegExp(`^${escaped}$`, 'i');
    filtered = filtered.filter((r) => pattern.test(r.fullName));
  }

  return filtered;
}

async function handleRepoCreate(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const repo = await deps.github.createRepo({
    name: args.name,
    description: args.description,
    private: args.private,
    template: args.template,
  });

  if (args.addToManaged) {
    deps.state.addManagedRepo({
      owner: repo.owner,
      name: repo.name,
      policies: ['default-branch-protection'],
    });
  }

  return repo;
}

async function handleRepoArchive(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  await deps.github.archiveRepo(args.owner, args.repo);
  return { archived: true, repo: `${args.owner}/${args.repo}` };
}

async function handleRepoDelete(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  if (args.confirm !== `${args.owner}/${args.repo}`) {
    throw new Error(
      `Confirmation failed. Type "${args.owner}/${args.repo}" to confirm deletion.`
    );
  }
  await deps.github.deleteRepo(args.owner, args.repo);
  deps.state.removeManagedRepo(args.owner, args.repo);
  return { deleted: true, repo: `${args.owner}/${args.repo}` };
}

async function handleRepoSettings(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  await deps.github.updateRepoSettings(args.owner, args.repo, {
    description: args.settings?.description,
    homepage: args.settings?.homepage,
    private: args.settings?.private,
    has_issues: args.settings?.hasIssues,
    has_projects: args.settings?.hasProjects,
    has_wiki: args.settings?.hasWiki,
    default_branch: args.settings?.defaultBranch,
  });
  return { updated: true, repo: `${args.owner}/${args.repo}` };
}

async function handleRepoCommit(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  if (!args.files || args.files.length === 0) {
    throw new Error('No files specified');
  }

  for (const file of args.files) {
    if (!file.delete && file.content === undefined) {
      throw new Error(`File ${file.path} has no content`);
    }
  }

  const branch = args.branch || 'main';
  const result = await deps.github.commitFiles(args.owner, args.repo, {
    branch,
    message: args.message,
    files: args.files.map((f: any) => ({
      path: f.path,
      content: f.content || '',
      delete: f.delete,
    })),
    createBranch: args.createBranch,
    baseBranch: args.baseBranch,
  });

  let pr = null;
  if (args.createPr && branch !== 'main' && branch !== 'master') {
    if (!args.prTitle) {
      throw new Error('prTitle is required when createPr is true');
    }

    pr = await deps.github.createPullRequest(args.owner, args.repo, {
      title: args.prTitle,
      body: args.prBody || '',
      head: branch,
      base: args.baseBranch || 'main',
      labels: args.prLabels,
    });
  }

  return {
    success: true,
    commit: {
      sha: result.sha,
      url: result.url,
    },
    branch,
    filesCommitted: args.files.length,
    pr: pr ? { number: pr.number, url: pr.url } : null,
  };
}

async function handleRepoReadFile(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const file = await deps.github.getFile(
    args.owner,
    args.repo,
    args.path,
    args.ref
  );

  if (!file) {
    return {
      found: false,
      path: args.path,
      message: 'File not found',
    };
  }

  return {
    found: true,
    path: args.path,
    content: file.content,
    sha: file.sha,
  };
}

async function handleRepoListFiles(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const files = await deps.github.listFiles(
    args.owner,
    args.repo,
    args.path || '',
    args.ref
  );

  return {
    path: args.path || '/',
    files: files,
    count: files.length,
  };
}

async function handleRepoScrubHistory(args: Record<string, any>, deps: ToolDeps): Promise<any> {
  const { execFileSync } = await import('child_process');
  const { mkdtempSync, rmSync } = await import('fs');
  const { tmpdir } = await import('os');
  const { join } = await import('path');

  const { owner, repo, paths, dryRun, confirm } = args;
  if (!paths || paths.length === 0) throw new Error('paths array must not be empty');

  if (!dryRun && confirm !== 'yes-rewrite-history') {
    throw new Error('This is a destructive operation that rewrites git history. Set confirm to "yes-rewrite-history" to proceed, or use dryRun: true to preview.');
  }

  try {
    execFileSync('git', ['filter-repo', '--version'], { encoding: 'utf8' });
  } catch {
    throw new Error('git-filter-repo is not installed. Install it with: brew install git-filter-repo (macOS) or pip install git-filter-repo');
  }

  const token = await deps.github.getInstallationToken();
  const cloneUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`;
  const tmpDir = mkdtempSync(join(tmpdir(), 'git-steer-scrub-'));

  try {
    execFileSync('git', ['clone', '--mirror', cloneUrl, tmpDir + '/repo.git'], {
      encoding: 'utf8',
      timeout: 120_000,
    });

    const filterArgs = ['filter-repo'];
    for (const p of paths) {
      filterArgs.push('--path', p);
    }
    filterArgs.push('--invert-paths', '--force');

    const filterOutput = execFileSync('git', filterArgs, {
      cwd: tmpDir + '/repo.git',
      encoding: 'utf8',
      timeout: 300_000,
    });

    if (dryRun) {
      return {
        dryRun: true,
        owner,
        repo,
        pathsPurged: paths,
        message: 'Dry run complete. History was rewritten locally but NOT pushed. The following paths would be purged from all history.',
        filterOutput: filterOutput || '(no output)',
      };
    }

    execFileSync('git', ['remote', 'add', 'origin', cloneUrl], {
      cwd: tmpDir + '/repo.git',
      encoding: 'utf8',
    });
    execFileSync('git', ['push', '--force', '--all', 'origin'], {
      cwd: tmpDir + '/repo.git',
      encoding: 'utf8',
      timeout: 300_000,
    });
    try {
      execFileSync('git', ['push', '--force', '--tags', 'origin'], {
        cwd: tmpDir + '/repo.git',
        encoding: 'utf8',
        timeout: 120_000,
      });
    } catch {
      // Tags push may fail if no tags exist
    }

    deps.state.addAuditEntry({
      action: 'repo_scrub_history',
      result: 'success',
      details: { owner, repo, pathsPurged: paths },
    });

    return {
      success: true,
      owner,
      repo,
      pathsPurged: paths,
      message: `History rewritten and force-pushed. ${paths.length} path(s) purged from all commits.`,
    };
  } finally {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}
