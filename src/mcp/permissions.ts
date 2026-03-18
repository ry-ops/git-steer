/**
 * Destructive tool classification and dry-run defaults.
 *
 * Per TAEM SECINSP finding SEC-010: ~50 MCP tools including repo_delete,
 * branch_reap, cert_renew are accessible to an LLM with zero permission tiers.
 */

export type ToolTier = 'read' | 'write' | 'destructive';

/** Tools classified as destructive — require explicit confirmation. */
export const DESTRUCTIVE_TOOLS: ReadonlySet<string> = new Set([
  'repo_delete',
  'repo_archive',
  'repo_scrub_history',
  'branch_reap',
  'cert_renew',
  'security_dismiss',
]);

/** Tools that default to dry_run=true when not explicitly set. */
export const DRY_RUN_DEFAULT_TOOLS: ReadonlySet<string> = new Set([
  'security_sweep',
  'security_fix_pr',
  'branch_reap',
  'oomkill_remediate',
]);
