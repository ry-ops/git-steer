# 🚜 git-steer

<img src="https://github.com/ry-ops/git-steer/blob/main/git-steer.png" width="100%">

**Self-hosting GitHub autonomy engine.** A skid steer for your repos.

git-steer gives you 100% autonomous control over your GitHub account through a Model Context Protocol (MCP) server. Manage repos, branches, security, Actions—everything—through natural language.

## Philosophy

**Your PC or Mac is just the steering wheel.** The engine lives on GitHub.

- **Zero local footprint**: Only Keychain credentials persist locally
- **Self-hosting code**: git-steer pulls itself from GitHub at runtime
- **State on GitHub**: All configuration and audit logs live in a private repo
- **GitHub Actions as cron**: Scheduled jobs run via Actions workflows

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR PC or MAC                           │
│                                                                 │
│   Keychain: GitHub App credentials (that's it)                  │
│                                                                 │
│   $ npx git-steer                                               │
│         │                                                       │
│         ├─► Pulls latest code from ry-ops/git-steer             │
│         ├─► Loads state from ry-ops/git-steer-state             │
│         ├─► Runs MCP server in-memory                           │
│         └─► Saves state back to GitHub on shutdown              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# First time setup
npx git-steer init

# This will:
# 1. Create a GitHub App with full permissions
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
| Claude config | `~/.config/claude/claude_desktop_config.json` |

That's it. No config files. No dotfiles. No `~/.git-steer`.

## State Repository

git-steer stores all state in a private repo (`git-steer-state`):

```
git-steer-state/
├── config/
│   ├── managed-repos.yaml    # Which repos git-steer controls
│   ├── policies.yaml         # Branch protection templates
│   └── schedules.yaml        # Scheduled job definitions
├── state/
│   ├── audit.jsonl           # Action log (append-only)
│   ├── jobs.jsonl            # Job history
│   └── cache.json            # Rate limits, ETags
└── .github/workflows/
    └── heartbeat.yml         # Scheduled job triggers
```

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
- `security_alerts` - List Dependabot/code scanning alerts
- `security_dismiss` - Dismiss alert with reason
- `security_digest` - Summary across all managed repos

### GitHub Actions
- `actions_workflows` - List workflows
- `actions_trigger` - Manually trigger a workflow
- `actions_secrets` - Manage Actions secrets

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

You: "Delete all branches older than 60 days in my mcp-unifi repo, except main"
Claude: [calls branch_reap with daysStale=60, exclude=['main']]

You: "Show me all critical security alerts across my projects"
Claude: [calls security_digest with severity='critical']

You: "Archive my old-project repo"
Claude: [calls repo_archive]

You: "Create a new MCP server repo from my template"
Claude: [calls repo_create with template]
```

## Claude Desktop Integration

Add to `~/.config/claude/claude_desktop_config.json`:

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

## License

MIT

---

Built by [ry-ops](https://github.com/ry-ops) • [Blog](https://ry-ops.dev)
