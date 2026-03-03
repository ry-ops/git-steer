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
export declare function listRepos(github: FabricGitHubAdapter, org?: string): Promise<{
    owner: string;
    name: string;
    fullName: string;
    private: boolean;
    defaultBranch: string;
    url: string;
    pushedAt?: string;
}[]>;
export declare function getFileContent(github: FabricGitHubAdapter, owner: string, repo: string, path: string, ref?: string): Promise<string | null>;
export declare function listFiles(github: FabricGitHubAdapter, owner: string, repo: string, path?: string, ref?: string): Promise<{
    path: string;
    type: string;
    size?: number;
    sha: string;
}[]>;
export declare function commitFiles(github: FabricGitHubAdapter, owner: string, repo: string, opts: {
    branch: string;
    message: string;
    files: {
        path: string;
        content: string;
    }[];
    createBranch?: boolean;
    fromBranch?: string;
}): Promise<{
    sha: string;
    url: string;
    branch: string;
}>;
export declare function listCommits(github: FabricGitHubAdapter, owner: string, repo: string, branch?: string, limit?: number): Promise<{
    sha: string;
    shortSha: string;
    message: string;
    author: string;
    date: string;
    url: string;
}[]>;
export declare function getCommit(github: FabricGitHubAdapter, owner: string, repo: string, sha: string): Promise<{
    sha: string;
    shortSha: string;
    message: string;
    author: string;
    date: string;
    additions: number;
    deletions: number;
    files: {
        filename: string;
        status: string;
        additions: number;
        deletions: number;
    }[];
}>;
export declare function compareCommits(github: FabricGitHubAdapter, owner: string, repo: string, base: string, head: string): Promise<{
    status: string;
    aheadBy: number;
    behindBy: number;
    commits: {
        sha: string;
        message: string;
    }[];
    files: {
        filename: string;
        status: string;
    }[];
}>;
export declare function listBranches(github: FabricGitHubAdapter, owner: string, repo: string): Promise<{
    name: string;
    sha: string;
    protected: boolean;
}[]>;
export declare function createBranch(github: FabricGitHubAdapter, owner: string, repo: string, branch: string, fromBranch: string): Promise<{
    owner: string;
    repo: string;
    branch: string;
    from: string;
}>;
export declare function deleteBranch(github: FabricGitHubAdapter, owner: string, repo: string, branch: string): Promise<{
    owner: string;
    repo: string;
    branch: string;
    deleted: true;
}>;
export declare function listPullRequests(github: FabricGitHubAdapter, owner: string, repo: string, state?: 'open' | 'closed' | 'all'): Promise<{
    number: number;
    title: string;
    state: string;
    author: string;
    head: string;
    base: string;
    url: string;
    draft: boolean;
}[]>;
export declare function getPullRequest(github: FabricGitHubAdapter, owner: string, repo: string, number: number): Promise<{
    number: number;
    title: string;
    state: string;
    body: string;
    author: string;
    head: string;
    base: string;
    url: string;
    draft: boolean;
    labels: string[];
    additions: number;
    deletions: number;
    changedFiles: number;
}>;
export declare function createPullRequest(github: FabricGitHubAdapter, owner: string, repo: string, opts: {
    title: string;
    head: string;
    base: string;
    body?: string;
    draft?: boolean;
    labels?: string[];
}): Promise<{
    number: number;
    url: string;
    state: string;
    draft: boolean;
}>;
export declare function mergePullRequest(github: FabricGitHubAdapter, owner: string, repo: string, number: number, method?: 'merge' | 'squash' | 'rebase', commitTitle?: string): Promise<{
    merged: boolean;
    sha?: string;
    message: string;
}>;
//# sourceMappingURL=git.d.ts.map