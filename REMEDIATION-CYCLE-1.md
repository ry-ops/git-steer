# TAEM Remediation — Cycle 1

**Mission:** `git-steer` Phase 04 Gate Clearance
**Source Report:** [TAEM-DEV/missions/git-steer.md](https://github.com/TAEM-DEV/missions/blob/main/git-steer.md)
**Gate Status:** NO-GO (SECINSP, TRC, PRB)
**Cycle:** 1 of 2 (ADR-003 C-003-004)
**Target:** `ry-ops/git-steer` @ `main`

---

## Blocking Findings — What Must Clear

| Controller | Signal | Blocking IDs |
|------------|--------|-------------|
| SECINSP | NO-GO | SEC-001, SEC-002, SEC-003, SEC-010 |
| TRC | NO-GO | Zero tool handler tests, zero coverage |
| PRB-SKP | NO-GO | Unguarded destructive tools, dual Octokit |
| PRB-ADR | NO-GO | Zero-footprint violations, credential model |

---

## Fix 1 — SEC-001: Token in `process.env` (P0)

**File:** `src/fabric/gateway.ts:35-37`

**Problem:** `initGateway()` writes the GitHub token into `process.env.GITHUB_TOKEN`, `process.env.STATE_REPO`, and `process.env.MANAGED_REPOS`. Any imported module, dependency, or child process can read it. This is the token equivalent of writing a password to a shared file.

**Fix:** Pass config directly to the CVE app factory instead of mutating the global environment.

```typescript
// gateway.ts — BEFORE (lines 34-37)
process.env.GITHUB_TOKEN = opts.githubToken;
process.env.STATE_REPO = opts.stateRepo;
process.env.MANAGED_REPOS = opts.managedRepos.join(',');
const registry = createRegistry();
const cveModule = await import('@git-fabric/cve');
const cveApp = await cveModule.createApp();

// gateway.ts — AFTER
const registry = createRegistry();
const cveModule = await import('@git-fabric/cve');
const cveApp = await cveModule.createApp({
  githubToken: opts.githubToken,
  stateRepo: opts.stateRepo,
  managedRepos: opts.managedRepos,
});
```

**If `@git-fabric/cve.createApp()` doesn't accept config args yet:** Update the CVE app's `createApp()` signature in `@git-fabric/cve` to accept an options object. The `createAdapterFromEnv()` pattern inside CVE should become `createAdapter(opts)` with env as fallback only. The gateway should never need to write env vars.

**Verification:** `grep -r 'process\.env\.' src/fabric/gateway.ts` returns zero matches after the fix.

---

## Fix 2 — SEC-002/SEC-003: Token Exposure via Adapter (P0)

**Files:**
- `src/fabric/adapter.ts:6` — `token: string` public property
- `src/fabric/git.ts` — 10+ functions constructing `Authorization: token ${github.token}` headers manually

**Problem:** The `FabricGitHubAdapter` interface exposes the raw token as a readable property. Every function in `git.ts` manually constructs auth headers via string interpolation, which means the token appears in stack traces if fetch fails.

**Fix:** Replace the `token` property with a `headers()` method that returns pre-built auth headers. The raw token is never visible to callers.

```typescript
// adapter.ts — AFTER
export interface FabricGitHubAdapter {
  /** Returns pre-built Authorization headers. Raw token is never exposed. */
  headers(): Record<string, string>;

  getFileContent(owner: string, repo: string, path: string): Promise<string | null>;
  commitFiles(owner: string, repo: string, opts: { ... }): Promise<{ sha: string; url: string }>;
  createBranch(owner: string, repo: string, branch: string, fromBranch: string): Promise<void>;
  createPullRequest(owner: string, repo: string, opts: { ... }): Promise<{ number: number; html_url: string; url: string }>;
}
```

```typescript
// git.ts — BEFORE (repeated 10+ times)
const headers = {
  Authorization: `token ${github.token}`,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
  'User-Agent': 'git-steer/fabric-git',
};

// git.ts — AFTER (every function)
const headers = github.headers();
```

The adapter implementation (wherever it's constructed — likely in `app.ts` or `index.ts`) stores the token privately and builds headers internally:

```typescript
class GitHubAdapterImpl implements FabricGitHubAdapter {
  private readonly _token: string;

  constructor(token: string) {
    this._token = token;
  }

  headers(): Record<string, string> {
    return {
      Authorization: `token ${this._token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'git-steer/fabric-git',
    };
  }
  // ... delegate methods
}
```

**Verification:** `grep -r '\.token' src/fabric/` returns zero matches for raw token access (only `_token` in the private implementation).

---

## Fix 3 — SEC-010 + PRB-SKP: Unguarded Destructive Tools (P0)

**File:** `src/mcp/server.ts` (3,204 lines)

**Problem:** ~50 MCP tools including `repo_delete`, `branch_reap`, `repo_scrub_history`, `cert_renew` (deletes K8s secrets) are all accessible to an LLM with zero permission tiers. The `repo_delete` "confirmation" is a string match an LLM trivially satisfies.

**Fix:** Add a destructive tool classification and dry-run default.

### 3a. Define a destructive tool registry

```typescript
// src/mcp/permissions.ts (new file)

export type ToolTier = 'read' | 'write' | 'destructive';

/** Tools classified as destructive — require explicit confirmation. */
export const DESTRUCTIVE_TOOLS: ReadonlySet<string> = new Set([
  'repo_delete',
  'repo_archive',
  'repo_scrub_history',
  'branch_reap',
  'cert_renew',        // deletes K8s secrets
  'security_dismiss',  // dismisses security alerts
]);

/** Tools that default to dry_run=true when not explicitly set. */
export const DRY_RUN_DEFAULT_TOOLS: ReadonlySet<string> = new Set([
  'security_sweep',
  'security_fix_pr',
  'branch_reap',
  'oomkill_remediate',
]);
```

### 3b. Add a guard in the CallToolRequest handler

In `server.ts`, the `CallToolRequestSchema` handler should check:

```typescript
// Inside the CallToolRequest handler, before dispatching to tool logic:

if (DESTRUCTIVE_TOOLS.has(toolName)) {
  const confirmValue = args.confirm as string | undefined;
  const expectedConfirm = `CONFIRM_${toolName.toUpperCase()}`;
  if (confirmValue !== expectedConfirm) {
    return {
      content: [{
        type: 'text',
        text: `⚠️ ${toolName} is a destructive operation. Pass confirm: "${expectedConfirm}" to proceed. This action cannot be undone.`,
      }],
    };
  }
}

if (DRY_RUN_DEFAULT_TOOLS.has(toolName) && args.dry_run === undefined) {
  args.dry_run = true;
}
```

### 3c. Add `confirm` to destructive tool schemas

Each destructive tool's `inputSchema.properties` must include:

```json
{
  "confirm": {
    "type": "string",
    "description": "Safety confirmation. Must be exactly 'CONFIRM_<TOOL_NAME>' to proceed."
  }
}
```

**Verification:** Call `repo_delete` without the correct confirm string → returns warning, not deletion. Call `security_sweep` without `dry_run` → defaults to `dry_run: true`.

---

## Fix 4 — CDS-001 + PRB-SKP: Dual Octokit (P1)

**Files:**
- `src/fabric/app.ts:39-41` — creates raw `new Octokit({ auth: token })` with zero throttling
- `src/github/client.ts` — the throttled, rate-aware `GitHubClient`

**Problem:** Two Octokit instances hitting the same GitHub API. The Fabric app's Octokit has zero rate-limit protection and could trigger secondary rate limits that throttle the main client.

**Fix:** `fabric/app.ts` should accept and use the same `GitHubClient` instance (or at minimum its throttled Octokit) rather than creating its own.

```typescript
// app.ts — BEFORE
function createOctokit(token: string): Octokit {
  return new Octokit({ auth: token });
}

export function createApp(tokenOverride?: string): FabricApp {
  const token = tokenOverride ?? process.env.GITHUB_TOKEN ?? ...;
  const octokit = createOctokit(token);

// app.ts — AFTER
export function createApp(opts: {
  octokit: Octokit;        // from GitHubClient — already throttled
  owner?: string;
}): FabricApp {
  const octokit = opts.octokit;
```

The `GitHubClient` should expose a `getOctokit(): Octokit` method (or a shared Octokit getter) so `createApp()` can reuse it.

Alternatively, if `app.ts` is only used via the Fabric gateway path: route all Fabric API calls through `fabric/git.ts` functions that use the adapter's `headers()` method, and have the adapter internally use the throttled client. This eliminates the raw Octokit entirely.

**Verification:** `grep -r 'new Octokit' src/` returns exactly one match — in `github/client.ts`.

---

## Fix 5 — ARCH-001/002: God Files (P1)

**Files:**
- `src/mcp/server.ts` — 3,204 lines, ~50 tool definitions + handlers
- `src/fabric/app.ts` — 573 lines, 17 tool implementations inline

**Problem:** Single files containing all tool definitions AND implementations. Unmaintainable and unreviewable.

**Fix:** Split into per-domain modules.

### MCP server split

```
src/mcp/
├── server.ts            # MCP protocol setup, transport init, tool dispatch router
├── tools/
│   ├── repos.ts         # repo_list, repo_create, repo_archive, repo_settings, repo_delete, repo_commit, repo_read_file, repo_list_files
│   ├── branches.ts      # branch_list, branch_protect, branch_reap
│   ├── prs.ts           # pr_list, pr_create, pr_merge, pr_dedup_check, pr_dedup_create
│   ├── security.ts      # security_alerts, security_digest, security_scan, security_sweep, security_dismiss, security_enforce, security_fix_pr
│   ├── actions.ts       # actions_workflows, actions_trigger, actions_secrets
│   ├── ops.ts           # steer_status, steer_sync, steer_logs, ops_metrics, dashboard_generate, report_generate
│   ├── k8s.ts           # oomkill_detect, oomkill_remediate, cert_check, cert_renew
│   ├── fabric-cve.ts    # fabric_cve_scan, fabric_cve_enrich, fabric_cve_triage, fabric_cve_queue, fabric_cve_compact, fabric_cve_stats
│   └── misc.ts          # slack_notify, slack_configure, code_quality_sweep, code_review, workflow_status
└── permissions.ts       # destructive tool registry (from Fix 3)
```

Each module exports:
```typescript
export function getTools(): Tool[] { ... }
export function handleCall(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<CallToolResult> { ... }
```

`server.ts` collects tools via `[...repos.getTools(), ...branches.getTools(), ...]` and dispatches via a name→handler map.

### Fabric app split

```
src/fabric/
├── app.ts               # createApp(), health check, tool aggregation
├── tools/
│   ├── repos.ts         # git_steer_repo_list, git_steer_repo_create, git_steer_repo_archive, git_steer_repo_settings
│   ├── branches.ts      # git_steer_branch_list, git_steer_branch_protect, git_steer_branch_reap
│   ├── prs.ts           # git_steer_pr_list, git_steer_pr_create, git_steer_pr_merge
│   ├── security.ts      # git_steer_security_alerts, git_steer_security_digest
│   └── actions.ts       # git_steer_actions_workflows, git_steer_actions_trigger
├── adapter.ts           # FabricGitHubAdapter interface (updated per Fix 2)
└── git.ts               # Low-level GitHub REST connector (updated per Fix 2)
```

**Verification:** `wc -l src/mcp/server.ts` < 300. `wc -l src/fabric/app.ts` < 100. No single tool module exceeds 400 lines.

---

## Fix 6 — TRC: Test Coverage (P1)

**Problem:** 5 test files testing isolated logic only. Zero tests for tool execution, state persistence, or MCP protocol handling. No coverage reporting.

**Fix:** Add integration tests for the top 10 most-used/most-dangerous MCP tools, and configure coverage.

### 6a. Add vitest coverage configuration

```typescript
// vitest.config.ts — add coverage block
export default defineConfig({
  test: {
    // ...existing config...
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/__tests__/**', 'src/**/*.d.ts'],
      thresholds: {
        lines: 60,
        functions: 60,
        branches: 50,
        statements: 60,
      },
    },
  },
});
```

### 6b. Add tool handler integration tests

Create `src/__tests__/tools/` with tests for these tools (priority order):

| Test File | Tools Covered | Why |
|-----------|--------------|-----|
| `repos.test.ts` | `repo_list`, `repo_create`, `repo_delete` | `repo_delete` is destructive — must test guard |
| `branches.test.ts` | `branch_list`, `branch_reap` | `branch_reap` is destructive — must test guard |
| `security.test.ts` | `security_sweep`, `security_alerts` | Most complex tool, dry-run default must work |
| `prs.test.ts` | `pr_list`, `pr_create`, `pr_merge` | Core workflow tools |
| `permissions.test.ts` | Destructive tool guard, dry-run defaults | Tests the permission tier from Fix 3 |

Each test should:
1. Mock the GitHub API (Octokit) — not the tool handler
2. Call the tool handler with valid and invalid args
3. Verify the destructive guard blocks without `confirm`
4. Verify `dry_run` defaults for sweep tools
5. Verify error cases return structured errors, not crashes

### 6c. Add MCP protocol integration test

Create `src/__tests__/mcp-protocol.test.ts` that:
1. Starts an in-process MCP server
2. Sends `ListToolsRequest` and verifies all tools are registered
3. Sends `CallToolRequest` for a read-only tool and verifies the response shape
4. Sends `CallToolRequest` for a destructive tool without confirm and verifies the guard

**Verification:** `npm run test -- --coverage` passes with all thresholds met. At least 10 tool handlers have dedicated tests.

---

## Fix 7 — PRB-ADR: Zero-Footprint Violations (P1)

**Problem:** `code_review` tool shells out to a local `cr` binary via `execFileSync`. K8s tools assume `kubectl` on PATH. These violate git-steer's "zero local footprint" principle.

**Fix:**

### 7a. `code_review` tool

If CodeRabbit has a REST API, use that instead of the local binary. If not, document `code_review` as a tool that requires `cr` on PATH and mark it as `optional` in the tool registry — it should not appear in `ListTools` unless the binary is found.

```typescript
// In the code_review tool definition:
// Only register if cr binary exists
if (existsSync(crPath)) {
  tools.push({ name: 'code_review', ... });
}
```

### 7b. K8s tools (`oomkill_detect`, `oomkill_remediate`, `cert_check`, `cert_renew`)

Same pattern — only register if `kubectl` is on PATH. These tools should be conditional, not always-visible:

```typescript
import { execFileSync } from 'child_process';

function kubectlAvailable(): boolean {
  try {
    execFileSync('kubectl', ['version', '--client', '--short'], { timeout: 5000 });
    return true;
  } catch { return false; }
}

// In tool registration:
if (kubectlAvailable()) {
  tools.push(...k8sTools);
}
```

This makes the tool surface honest — you only see tools that can actually execute.

**Verification:** Start the MCP server without `kubectl` on PATH → K8s tools do not appear in `ListTools`. Start without `cr` → `code_review` does not appear.

---

## Execution Order

Per TAEM ADR-003, fixes must be applied in dependency order:

1. **Fix 2** (adapter.ts + git.ts) — interface change that other fixes depend on
2. **Fix 1** (gateway.ts) — depends on adapter pattern being established
3. **Fix 3** (permissions.ts) — new file, no deps
4. **Fix 5** (god file split) — restructures server.ts and app.ts
5. **Fix 4** (dual Octokit) — easier after the split
6. **Fix 7** (conditional tools) — easier after the split
7. **Fix 6** (tests) — must be last, tests the final state

---

## Re-Review Gate Criteria

After Cycle 1, TAEM re-runs Phase 04. To clear:

| Controller | Required Signal | Criteria |
|------------|----------------|----------|
| SECINSP | GO | SEC-001 through SEC-003 resolved. SEC-010 mitigated by permission tier. No token in `process.env`, no raw token in interface, destructive tools gated. |
| TRC | GO | ≥10 tool handler tests, MCP protocol integration test, coverage ≥60% lines. |
| PRB-SKP | GO | Single Octokit, destructive tools gated, dry-run defaults. |
| PRB-COR | GO (maintain) | Internal consistency preserved after refactor. |
| PRB-ADR | GO | Conditional tool registration for local-binary tools. |

**PRB expected: 3/3 GO → ADVANCE**

---

## Out of Scope — Cycle 2

These are real findings but not blocking. Deferred per ADR-003 C-003-004:

- SEC-004 (Slack webhook URL validation)
- SEC-005 (`npm audit fix --force` in CI)
- SEC-011 (workflow dispatch injection)
- DPS (Zod schemas for MCP inputs)
- CDS-003 (state write conflict model)
- ARCH-005 (hardcoded owner)
- ARCH-006 (`dist/` in source)

---

*Prepared for TAEM kernel execution. Cycle 1 of 2.*
