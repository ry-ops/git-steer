/**
 * Gateway integration
 *
 * Initializes the @git-fabric/gateway, loads the CVE app,
 * and returns a handle for routing tool calls.
 *
 * Catches all errors — never crashes git-steer.
 * When the gateway fails to initialize, tools are simply omitted.
 */
import type { Router } from '@git-fabric/gateway';
export interface GatewayHandle {
    router: Router;
    available: boolean;
    appCount: number;
    toolCount: number;
}
export declare function initGateway(opts: {
    githubToken: string;
    stateRepo: string;
    managedRepos: string[];
}): Promise<GatewayHandle>;
//# sourceMappingURL=gateway.d.ts.map