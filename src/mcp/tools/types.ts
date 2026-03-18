/**
 * Shared dependency interface for tool modules.
 *
 * Each domain module receives a ToolDeps bag so it can access
 * the GitHub client, state manager, gateway, and helper utilities
 * without importing them directly.
 */

import type { GitHubClient, RateLimitSnapshot } from '../../github/client.js';
import type { StateManager } from '../../state/manager.js';
import type { GatewayHandle } from '../../fabric/gateway.js';

export interface ToolDeps {
  github: GitHubClient;
  state: StateManager;
  gateway: GatewayHandle | null;
  rateLimitCache: RateLimitSnapshot | null;
  refreshRateLimit: () => Promise<void>;
  sendSlackNotification: (webhookUrl: string, payload: Record<string, any>) => Promise<void>;
  readLimit: <T>(fn: () => Promise<T>) => Promise<T>;
  writeLimit: <T>(fn: () => Promise<T>) => Promise<T>;
}

export interface ToolResult {
  content: { type: string; text: string }[];
}
