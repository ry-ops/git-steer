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
export declare function createApp(tokenOverride?: string): FabricApp;
export {};
//# sourceMappingURL=app.d.ts.map