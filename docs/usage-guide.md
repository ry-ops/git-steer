# Usage Guide

This guide covers how to use git-steer with Claude Desktop, all available MCP tools, and example prompts.

## Claude Desktop Integration

### Setup

Add git-steer to your Claude Desktop configuration:

**macOS:** `~/.config/claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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

### Restart Claude Desktop

After editing the config, fully restart Claude Desktop (not just close the window).

### Verify Connection

In Claude Desktop, you should see git-steer listed under available tools. Try:

**You:** "What git-steer tools do you have available?"

Claude will list all available MCP tools.

## MCP Tools Reference

### Repository Management

| Tool | Description | Required Permission |
|------|-------------|---------------------|
| `repo_list` | List all accessible repositories | Metadata: Read |
| `repo_create` | Create new repo (optionally from template) | Administration: Write |
| `repo_archive` | Archive a repository | Administration: Write |
| `repo_delete` | Permanently delete (requires confirmation) | Administration: Write |
| `repo_settings` | Update repo settings | Administration: Write |

### Branch Operations

| Tool | Description | Required Permission |
|------|-------------|---------------------|
| `branch_list` | List branches with staleness info | Contents: Read |
| `branch_protect` | Apply protection rules | Administration: Write |
| `branch_reap` | Delete stale/merged branches | Contents: Write |

### Security

| Tool | Description | Required Permission |
|------|-------------|---------------------|
| `security_alerts` | List Dependabot/code scanning alerts | Security events: Read |
| `security_dismiss` | Dismiss alert with reason | Security events: Write |
| `security_digest` | Summary across all managed repos | Security events: Read |
| `security_scan` | Scan repos for vulnerabilities | Security events: Read |
| `security_fix_pr` | Create PR to fix vulnerabilities | Contents: Write |

### GitHub Actions

| Tool | Description | Required Permission |
|------|-------------|---------------------|
| `actions_workflows` | List workflows | Actions: Read |
| `actions_trigger` | Manually trigger a workflow | Actions: Write |
| `actions_secrets` | Manage Actions secrets | Actions: Write |

### Configuration & Status

| Tool | Description | Required Permission |
|------|-------------|---------------------|
| `config_show` | Display current config | None (reads state repo) |
| `config_add_repo` | Add repo to managed list | None (writes state repo) |
| `config_remove_repo` | Remove from managed list | None (writes state repo) |
| `steer_status` | Health and rate limits | None |
| `steer_sync` | Force save state to GitHub | None |
| `steer_logs` | View audit log | None |

## Example Prompts

### Repository Management

**List repos:**
> "Show me all my repos"
> "List repos I haven't touched in 6 months"
> "Which repos have the most open issues?"

**Create repos:**
> "Create a new repo called my-new-project"
> "Create a repo from my mcp-template template"
> "Create a private repo called secret-stuff"

**Archive/delete:**
> "Archive my old-experiments repo"
> "Delete the test-repo repository" (requires confirmation)

### Branch Operations

**List branches:**
> "Show me all branches in my-api"
> "Which branches are stale in my-frontend?"
> "List branches older than 60 days"

**Clean up branches:**
> "Delete all merged branches in my-api"
> "Clean up branches older than 30 days, but keep main and develop"
> "Do a dry run of branch cleanup for my-frontend"

**Protection:**
> "Protect the main branch of my-api"
> "Require 2 reviews on main for my-frontend"
> "Apply strict-protection policy to all my repos"

### Security

**Alerts:**
> "Show me all critical security alerts"
> "What Dependabot alerts do I have?"
> "Give me a security digest across all my projects"

**Dismissing:**
> "Dismiss alert #123 in my-api as tolerable risk"
> "Mark the lodash vulnerability as fix_started"

### GitHub Actions

**Workflows:**
> "List workflows in my-api"
> "What CI checks does my-frontend have?"

**Triggering:**
> "Trigger the deploy workflow in my-api"
> "Run the nightly build for my-frontend"

**Secrets:**
> "List secrets in my-api"
> "Add a new secret called API_KEY to my-frontend"
> "Delete the old DATABASE_URL secret"

### Configuration

**Viewing:**
> "Show my git-steer config"
> "What repos am I managing?"
> "What policies do I have defined?"

**Managing:**
> "Add my-new-repo to managed repos"
> "Remove old-repo from git-steer"
> "Apply the security-alerts policy to all my repos"

### Status & Logs

**Health:**
> "What's the git-steer status?"
> "How many API calls do I have left?"

**Logs:**
> "Show me recent git-steer actions"
> "What did git-steer do yesterday?"

## Natural Language Tips

git-steer understands natural language, so you don't need to memorize exact commands:

**These all work:**
> "clean up old branches" = `branch_reap`
> "protect main" = `branch_protect`
> "show security issues" = `security_alerts` or `security_digest`
> "make a new repo" = `repo_create`

**Be specific when needed:**
> "Delete branches older than 60 days" → sets `daysStale: 60`
> "Keep main and develop" → sets `exclude: ["main", "develop"]`
> "Do a dry run first" → sets `dryRun: true`

## Confirmation Prompts

Some actions require confirmation:

**Destructive actions:**
- `repo_delete` - Always requires typing the repo name to confirm
- `branch_reap` - Will list branches first and ask for confirmation (unless dry run)
- `actions_secrets delete` - Confirms before removing

**Example:**
> **You:** "Delete my test-repo"
> **Claude:** "This will permanently delete test-repo and all its contents. Type 'test-repo' to confirm."
> **You:** "test-repo"
> **Claude:** *[executes repo_delete]*

## Dry Run Mode

Many destructive operations support dry run:

> "Do a dry run of branch cleanup for my-api"
> "Show me what would be archived without actually archiving"

This lets you preview changes before committing to them.

## Working with Multiple Repos

**Batch operations:**
> "Clean up stale branches in all my managed repos"
> "Show security alerts across all projects"
> "Apply standard-protection to every repo"

**Filtering:**
> "List only my Python repos"
> "Show repos with failing CI"
> "Which repos have open Dependabot PRs?"

## Offline Mode

If you lose internet connection, git-steer continues with cached state:

- Read operations work (listing repos, branches, alerts)
- Write operations queue until you're back online
- Run `npx git-steer sync` when reconnected

---

**Having issues?** Check the [Troubleshooting](troubleshooting.md) guide.
