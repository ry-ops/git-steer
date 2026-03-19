# git-steer

<img src="git-steer-banner.svg" width="100%">

**Self-hosting GitHub autonomy engine.** A skid steer for your repos.

git-steer gives you autonomous control over your GitHub account through a Model Context Protocol (MCP) server. Manage repos, branches, security, Actions -- everything -- through natural language. Rate-limit-hardened from the ground up: ETag caching, GraphQL batching, concurrency caps, and chunked execution keep it well inside GitHub's API guardrails at any fleet size.

Passed [TAEM Phase 04 gate review](https://github.com/TAEM-DEV/missions/blob/main/git-steer.md) after two remediation cycles covering security, architecture, and test coverage.

## Philosophy: Zero Footprint

**Your machine steers. GitHub does everything else.**

Nothing lives locally -- no cloned repos, no config files, no build artifacts. git-steer treats your PC or Mac as a thin control plane and GitHub as the entire runtime.

- **Zero local code**: No repos cloned, no `node_modules`, no lock files
- **Keychain only**: GitHub App credentials in macOS Keychain -- nothing else on disk
- **Git as database**: All config, state, and audit logs live in a private GitHub repo
- **Actions as compute**: Dependency fixes, linting, and PRs happen in ephemeral cloud runners
- **Rate-limit-hardened**: Throttle/retry plugins, ETag caching, GraphQL batching, concurrency caps -- safe at any fleet size

```
+-----------------------------------------------------------------+
|                        YOUR PC or MAC                           |
|                                                                 |
|   Keychain:                                                     |
|     - GitHub App private key                                    |
|     - App ID / Installation ID                                  |
|                                                                 |
|   $ npx git-steer                  (stdio -> Claude Desktop)    |
|   $ npx git-steer --http           (portal -> localhost:3333)   |
|         |                                                       |
|         +-> Pulls itself from ry-ops/git-steer                  |
|         +-> Pulls state from ry-ops/git-steer-state             |
|         +-> Runs MCP server in-memory (rate-limit-aware)        |
|         +-> Commits state changes back on shutdown              |
|                                                                 |
+-----------------------------------------------------------------+
                               |
                    Throttled, ETag-cached,
                    GraphQL-batched API calls
                               |
                               v
+-----------------------------------------------------------------+
|                         GITHUB                                  |
|                                                                 |
|   ry-ops/git-steer              (source of truth for code)      |
|   |                                                             |
|   ry-ops/git-steer-state        (private repo)                  |
|   +-- config/                                                   |
|   |   +-- policies.yaml         (branch protection templates)   |
|   |   +-- schedules.yaml        (job definitions)               |
|   |   +-- managed-repos.yaml    (what git-steer controls)       |
|   +-- state/                                                    |
|   |   +-- jobs.jsonl            (job history, append-only)      |
|   |   +-- audit.jsonl           (action log + rate telemetry)   |
|   |   +-- rfcs.jsonl            (RFC lifecycle tracking)        |
|   |   +-- quality.jsonl         (linter/SAST results)           |
|   |   +-- cache.json            (ETag map + sweep cursor)       |
|   +-- .github/workflows/                                        |
|       +-- heartbeat.yml         (scheduled triggers)            |
|                                                                 |
+-----------------------------------------------------------------+
```

## Architecture

### Tool Module System

The MCP server is split into per-domain tool modules under `src/mcp/tools/`. Each module exports `getTools()` (tool definitions) and `handleCall()` (tool execution). The server collects tools from all modules at startup and dispatches via a name-to-handler map.

```
src/mcp/
+-- server.ts            # MCP protocol, transport init, tool dispatch (~600 lines)
+-- permissions.ts       # Destructive tool registry, dry-run defaults
+-- tools/
    +-- index.ts         # Re-exports all domain modules
    +-- types.ts         # Shared ToolDeps interface
    +-- repos.ts         # Repository management (8 tools)
    +-- branches.ts      # Branch operations (3 tools)
    +-- prs.ts           # Pull request workflows (3 tools -- was 5 with dedup)
    +-- security.ts      # Security scanning and sweeps (7 tools)
    +-- actions.ts       # GitHub Actions (3 tools)
    +-- ops.ts           # Observability, config, reports (8 tools)
    +-- k8s.ts           # Kubernetes ops (4 tools, conditional)
    +-- misc.ts          # Slack, code review, quality (5 tools)
```

Fabric tools (CVE pipeline and git operations) are defined in `server.ts` and delegated to `@git-fabric/cve` and the `FabricGitHubAdapter` at runtime.

All modules receive a `ToolDeps` bag containing the GitHub client, state manager, gateway handle, rate limit helpers, and concurrency limiters -- no direct imports of shared state.

## MCP Tools

42 core tools + 20 fabric tools, organized by domain.

### Repos (repos.ts)

| Tool | Description |
|------|-------------|
| `repo_list` | List all accessible repositories |
| `repo_create` | Create new repo (optionally from template) |
| `repo_archive` | Archive a repository *(destructive)* |
| `repo_delete` | Permanently delete a repository *(destructive)* |
| `repo_scrub_history` | Rewrite repo history to remove sensitive data *(destructive)* |
| `repo_settings` | Update repo settings (visibility, features, merge options) |
| `repo_commit` | Commit files directly via GitHub API (no local clone) |
| `repo_read_file` | Read a file from a repository *(ETag-cached)* |
| `repo_list_files` | List files in a directory |

### Branches (branches.ts)

| Tool | Description |
|------|-------------|
| `branch_list` | List branches with staleness info *(GraphQL-batched)* |
| `branch_protect` | Apply protection rules |
| `branch_reap` | Delete stale/merged branches *(destructive, dry-run default)* |

### Pull Requests (prs.ts)

| Tool | Description |
|------|-------------|
| `pr_dedup_check` | Check if a PR already exists for a branch |
| `pr_dedup_create` | Create PR only if one doesn't already exist |

### Security (security.ts)

| Tool | Description |
|------|-------------|
| `security_scan` | Scan repos for vulnerabilities with fix info |
| `security_alerts` | List Dependabot/code scanning alerts |
| `security_digest` | Summary across all managed repos |
| `security_sweep` | Full autonomous pipeline: scan, RFC, fix PR, track *(dry-run default)* |
| `security_fix_pr` | Dispatch workflow to fix vulnerabilities *(dry-run default)* |
| `security_dismiss` | Dismiss alert with reason *(destructive)* |
| `security_enforce` | Ensure Dependabot alerts + automated fixes are enabled |

### Actions (actions.ts)

| Tool | Description |
|------|-------------|
| `actions_workflows` | List workflows |
| `actions_trigger` | Manually trigger a workflow |
| `actions_secrets` | Manage Actions secrets |

### Ops and Observability (ops.ts)

| Tool | Description |
|------|-------------|
| `config_show` | Display current config |
| `config_add_repo` | Add repo to managed list (auto-enables Dependabot) |
| `config_remove_repo` | Remove from managed list |
| `steer_status` | Health check with full rate limit budget |
| `steer_sync` | Force save state to GitHub |
| `steer_logs` | View audit log with rate limit telemetry |
| `ops_metrics` | Operational metrics and statistics |
| `dashboard_generate` | Interactive security dashboard, deployed to GitHub Pages |
| `report_generate` | Compliance reports (executive summary, change records, vulnerability, full audit) |

### Kubernetes (k8s.ts) -- conditional

Only registered when `kubectl` is on PATH. Not visible in `ListTools` otherwise.

| Tool | Description |
|------|-------------|
| `oomkill_detect` | Detect OOMKill events in the cluster |
| `oomkill_remediate` | Adjust resource limits for OOMKilled pods *(dry-run default)* |
| `cert_check` | Check TLS certificate expiry |
| `cert_renew` | Renew TLS certificates *(destructive)* |

### Misc (misc.ts) -- partially conditional

`code_review` only registered when the `cr` (CodeRabbit) binary is on PATH.

| Tool | Description |
|------|-------------|
| `slack_notify` | Send a Slack notification |
| `slack_configure` | Configure default Slack webhook |
| `code_quality_sweep` | Run linters/SAST via GitHub Actions |
| `code_review` | AI-powered code review via CodeRabbit CLI *(conditional)* |
| `workflow_status` | Check status of dispatched workflows |

### Fabric CVE (via @git-fabric/cve)

| Tool | Description |
|------|-------------|
| `fabric_cve_scan` | Scan managed repos against GitHub Advisory Database |
| `fabric_cve_enrich` | Fetch enriched CVE details from NVD |
| `fabric_cve_triage` | Process pending CVE queue: apply policy, open PRs |
| `fabric_cve_queue` | List CVE queue entries by status/severity |
| `fabric_cve_stats` | CVE queue health dashboard |
| `fabric_cve_compact` | Compact resolved entries from the queue |

### Fabric Git (via FabricGitHubAdapter)

14 tools for direct GitHub operations (`fabric_git_list_repos`, `fabric_git_get_file`, `fabric_git_commit_files`, `fabric_git_list_commits`, `fabric_git_get_commit`, `fabric_git_compare_commits`, `fabric_git_list_branches`, `fabric_git_create_branch`, `fabric_git_delete_branch`, `fabric_git_list_files`, `fabric_git_list_pull_requests`, `fabric_git_get_pull_request`, `fabric_git_create_pull_request`, `fabric_git_merge_pull_request`).

## Security Model

### Destructive tool confirmation

Tools classified as destructive require an explicit `confirm` parameter set to `CONFIRM_<TOOL_NAME>` (e.g., `CONFIRM_REPO_DELETE`). Without it, the tool returns a warning and takes no action. Destructive tools: `repo_delete`, `repo_archive`, `repo_scrub_history`, `branch_reap`, `cert_renew`, `security_dismiss`.

### Dry-run defaults

Sweep and remediation tools default to `dry_run: true` when the caller does not set it explicitly. This means an LLM cannot accidentally trigger writes without intent. Affected tools: `security_sweep`, `security_fix_pr`, `branch_reap`, `oomkill_remediate`.

### Token isolation

The `FabricGitHubAdapter` interface exposes a `headers()` method that returns pre-built Authorization headers. The raw token is never visible to callers -- it stays private inside the adapter implementation. The gateway no longer writes tokens to `process.env`.

### Slack webhook allowlist

Slack webhook URLs are validated against an allowlist (`hooks.slack.com`, `hooks.slack-gov.com`). Arbitrary URLs are rejected.

### Conditional tool registration

K8s tools (`oomkill_detect`, `oomkill_remediate`, `cert_check`, `cert_renew`) are only registered when `kubectl` is found on PATH. `code_review` is only registered when the `cr` binary is available. Tools that cannot execute are not advertised.

## Quick Start

```bash
# First time setup
npx git-steer init

# This will:
# 1. Create a GitHub App with required permissions
# 2. Install it to your account
# 3. Create a private git-steer-state repo
# 4. Store credentials in macOS Keychain

# Start the MCP server
npx git-steer
```

## Claude Desktop Integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "git-steer": {
      "command": "npx",
      "args": ["git-steer"]
    }
  }
}
```

Or use a local checkout:

```json
{
  "mcpServers": {
    "git-steer": {
      "command": "node",
      "args": ["/path/to/git-steer/bin/cli.js", "start", "--stdio"]
    }
  }
}
```

## Local Portal

git-steer includes an HTTP/SSE transport mode that exposes the MCP server as a local web portal:

```bash
git-steer start --http               # Default port 3333
git-steer start --http --port 8080   # Custom port
```

Endpoints: `/dashboard` (live security dashboard), `/mcp` (Streamable HTTP, protocol 2025-11), `/sse` + `/messages` (legacy SSE, protocol 2024-11), `/health` (JSON status).

The portal uses the same Keychain credentials, same state repo, and same rate-limit-hardened API stack as stdio mode.

## Rate-Limit Hardening

Seven-layer API safety stack:

1. **Throttle/Retry** -- Primary (429) auto-retry up to 4x, secondary (403) always back off, transient 5xx exponential backoff
2. **Concurrency caps** -- Writes max 2, reads max 8, search serial (via p-limit)
3. **ETag caching** -- Contents API sends If-None-Match, 304 avoids rate cost, persisted across restarts
4. **GraphQL batching** -- Owner resolution, branch listing, Dependabot alerts batched into single calls
5. **Rate budget visibility** -- `steer_status` shows all buckets with % remaining, warns below 15%
6. **Audit telemetry** -- Every action logged with rate_remaining, retry_count, backoff_ms
7. **Chunked sweep** -- `security_sweep(chunkSize: 10)` processes in batches, cursor persisted for `resume: true`

## Testing

42 tests passing across 7 test files. Vitest with v8 coverage provider, 60% floor on lines/functions/statements, 50% on branches.

```bash
npm test              # Run all tests
npm run test:coverage # Run with coverage report
```

## GitHub App Permissions Required

- **Repository**: Read & Write (contents, metadata)
- **Pull Requests**: Read & Write
- **Issues**: Read & Write (for RFC tracking)
- **Actions**: Read & Write (for workflow dispatch)
- **Dependabot alerts**: Read & Write
- **Code scanning alerts**: Read
- **Secrets**: Read & Write (for Actions secrets)
- **Administration**: Read & Write (for repo settings)
- **Pages**: Read & Write (for dashboard deployment)

## Commands

```bash
git-steer init                       # First-time setup
git-steer                            # Start MCP server via stdio (Claude Desktop)
git-steer start --http               # Start local portal on port 3333
git-steer start --http --port 8080   # Start portal on custom port
git-steer scan                       # Run security scan across all repos
git-steer scan --repo owner/name     # Scan a specific repo
git-steer scan --severity critical   # Filter by severity
git-steer status                     # Show status + rate limit budget
git-steer sync                       # Force sync state to GitHub
git-steer reset                      # Remove local credentials
```

## License

MIT

---

Built by [ry-ops](https://github.com/ry-ops)
