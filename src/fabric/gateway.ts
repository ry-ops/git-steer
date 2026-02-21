/**
 * Gateway integration
 *
 * Initializes the @git-fabric/gateway, loads the CVE app,
 * and returns a handle for routing tool calls.
 *
 * Catches all errors — never crashes git-steer.
 * When the gateway fails to initialize, tools are simply omitted.
 */

import { createRegistry, createRouter } from '@git-fabric/gateway';
import type { Router } from '@git-fabric/gateway';

export interface GatewayHandle {
  router: Router;
  available: boolean;
  appCount: number;
  toolCount: number;
}

export async function initGateway(opts: {
  githubToken: string;
  stateRepo: string;
  managedRepos: string[];
}): Promise<GatewayHandle> {
  const degraded: GatewayHandle = {
    router: null as unknown as Router,
    available: false,
    appCount: 0,
    toolCount: 0,
  };

  try {
    // Set env vars for CVE app's createAdaptersFromEnv()
    process.env.GITHUB_TOKEN = opts.githubToken;
    process.env.STATE_REPO = opts.stateRepo;
    process.env.MANAGED_REPOS = opts.managedRepos.join(',');

    const registry = createRegistry();

    // Dynamically import + register CVE app
    const cveModule = await import('@git-fabric/cve');
    const cveApp = await cveModule.createApp();
    registry.register(cveApp);

    const router = createRouter(registry);
    const tools = router.listTools();

    console.log(
      `[git-steer] Fabric gateway loaded: ${registry.list().length} app(s), ${tools.length} tool(s)`,
    );

    return {
      router,
      available: true,
      appCount: registry.list().length,
      toolCount: tools.length,
    };
  } catch (err: unknown) {
    console.warn(
      `[git-steer] Fabric gateway unavailable: ${(err as Error).message}`,
    );
    return degraded;
  }
}
