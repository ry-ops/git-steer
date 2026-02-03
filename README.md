# git-steer

[\![Version](https://img.shields.io/github/v/release/ry-ops/git-steer?style=flat-square)](https://github.com/ry-ops/git-steer/releases)
[\![License](https://img.shields.io/github/license/ry-ops/git-steer?style=flat-square)](LICENSE)
[\![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue?style=flat-square&logo=typescript&logoColor=white)](https://typescriptlang.org)
[\![MCP](https://img.shields.io/badge/MCP-Server-00A67E?style=flat-square)](https://modelcontextprotocol.io)


<img src="https://github.com/ry-ops/git-steer/blob/main/git-steer.png" width="100%">

**Self-hosting GitHub autonomy engine.** A skid steer for your repos.

git-steer gives you 100% autonomous control over your GitHub account through a Model Context Protocol (MCP) server. Manage repos, branches, security, Actions—everything—through natural language.

## Philosophy: Bare Tin Foil

**Your PC or Mac is just the steering wheel.** The engine lives on GitHub.

- **Zero local code**: No repos cloned to your machine
- **Keychain only**: Just GitHub App credentials stored locally
- **Git as database**: All state lives in a private repo
- **Actions as compute**: Code changes happen in ephemeral cloud workers

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR PC or MAC                            │
│                                                                  │
│   Keychain:                                                      │
│     - GitHub App private key                                     │
│     - App ID / Installation ID                                   │
│                                                                  │
│   $ npx git-steer                                                │
│         │                                                        │
│         ├─► Pulls itself from ry-ops/git-steer                   │
│         ├─► Pulls state from ry-ops/git-steer-state              │
│         ├─► Runs MCP server in-memory                            │
│         └─► Commits state changes back on shutdown               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         GITHUB                                   │
│                                                                  │
│   ry-ops/git-steer              (source of truth for code)       │
│   │                                                              │
│   ry-ops/git-steer-state        (private repo)                   │
│   ├── config/                                                    │
│   │   ├── policies.yaml         (branch protection templates)    │
│   │   ├── schedules.yaml        (job definitions)                │
│   │   └── managed-repos.yaml    (what git-steer controls)        │
│   ├── state/                                                     │
│   │   ├── jobs.jsonl            (job history, append-only)       │
│   │   ├── audit.jsonl           (action log)                     │
│   │   └── cache.json            (rate limits, etags)             │
│   └── .github/workflows/                                         │
│       └── heartbeat.yml         (scheduled triggers)             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## How Code Changes Work

When you ask git-steer to fix security vulnerabilities or make other code changes, it **dispatches a GitHub Actions workflow** instead of cloning code locally:

```
┌─────────────────────────────────────────────────────────────────┐
│  YOUR MAC (MCP triggers intent)                                  │
│                                                                  │
│  Claude: "Fix security vulnerabilities in cortex"                │
│       │                                                          │
│       ▼                                                          │
│  git-steer MCP: security_fix_pr(repo: "cortex", ...)             │
│       │                                                          │
│       └─► Dispatches workflow to GitHub Actions                  │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  GITHUB ACTIONS (ephemeral compute)                              │
│                                                                  │
│  .github/workflows/security-fix.yml:                             │
│    - Checkout target repo                                        │
│    - Update dependencies                                         │
│    - npm install / uv lock                                       │
│    - Run tests                                                   │
│    - Create branch, commit, push                                 │
│    - Open PR                                                     │
│    - Report status back to git-steer-state                       │
└─────────────────────────────────────────────────────────────────┘
```

Your Mac stays clean. No `node_modules`. No Python venvs. No lock files. Just pure orchestration.

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

## Local Footprint

| Item | Location |
|------|----------|
| GitHub App ID | macOS Keychain |
| Installation ID | macOS Keychain |
| Private Key | macOS Keychain |
| Claude config | `~/Library/Application Support/Claude/claude_desktop_config.json` |

That's it. No config files. No dotfiles. No `~/.git-steer`. No cloned repos.

## MCP Tools

### Repository Management
- `repo_list` - List all accessible repositories
- `repo_create` - Create new repo (optionally from template)
- `repo_archive` - Archive a repository
- `repo_delete` - Permanently delete (requires confirmation)
- `repo_settings` - Update repo settings

### Branch Operations
- `branch_list` - List branches with staleness info
- `branch_protect` - Apply protection rules
- `branch_reap` - Delete stale/merged branches

### Security
- `security_scan` - Scan repos for vulnerabilities with fix info
- `security_fix_pr` - **Dispatch workflow** to fix vulnerabilities
- `security_alerts` - List Dependabot/code scanning alerts
- `security_dismiss` - Dismiss alert with reason
- `security_digest` - Summary across all managed repos

### GitHub Actions
- `actions_workflows` - List workflows
- `actions_trigger` - Manually trigger a workflow
- `actions_secrets` - Manage Actions secrets
- `workflow_status` - Check status of dispatched workflows

### Configuration
- `config_show` - Display current config
- `config_add_repo` - Add repo to managed list
- `config_remove_repo` - Remove from managed list
- `steer_status` - Health and rate limits
- `steer_sync` - Force save state to GitHub
- `steer_logs` - View audit log

## Example Usage

```
You: "List all my repos"
Claude: [calls repo_list]

You: "Scan all my repos for security vulnerabilities"
Claude: [calls security_scan with repo="*"]

You: "Fix the critical vulnerabilities in cortex"
Claude: [calls security_fix_pr - dispatches workflow to GitHub Actions]

You: "Check the status of the fix"
Claude: [calls workflow_status]

You: "Delete all branches older than 60 days in mcp-unifi, except main"
Claude: [calls branch_reap with daysStale=60, exclude=['main']]

You: "Archive my old-project repo"
Claude: [calls repo_archive]
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

## GitHub App Permissions Required

The git-steer GitHub App needs these permissions:

- **Repository**: Read & Write (contents, metadata)
- **Pull Requests**: Read & Write
- **Actions**: Read & Write (for workflow dispatch)
- **Dependabot alerts**: Read
- **Secrets**: Read & Write (for Actions secrets)
- **Administration**: Read & Write (for repo settings)

## Setting Up Secrets

For the security-fix workflow to authenticate to target repos, add these secrets to the git-steer repo:

1. `GIT_STEER_APP_ID` - Your GitHub App ID
2. `GIT_STEER_PRIVATE_KEY` - Your GitHub App private key

These allow the workflow to generate installation tokens for any repo in your installation.

## Commands

```bash
git-steer init     # First-time setup
git-steer          # Start MCP server (default)
git-steer status   # Show status
git-steer sync     # Force sync state to GitHub
git-steer reset    # Remove local credentials
```

## Offline Behavior

When offline, git-steer runs in read-only mode with cached state. Write operations queue until next online session.

## Security

- All GitHub API access through a dedicated GitHub App
- Credentials stored in macOS Keychain (syncs via iCloud Keychain if enabled)
- Full audit log of all actions in state repo
- No secrets in code or config files
- No code stored locally - everything ephemeral

## License

MIT

---

Built by [ry-ops](https://github.com/ry-ops)
