# Security

git-steer is designed with security as a core principle. This guide explains how it protects your credentials and repositories.

## Security Model

```
┌──────────────────────────────────────────────────────────────────┐
│                     YOUR CONTROL                                  │
│                                                                   │
│  ┌─────────────────┐    ┌─────────────────┐    ┌──────────────┐  │
│  │  GitHub App     │    │  Repository     │    │  Audit Log   │  │
│  │  Permissions    │───▶│  Access List    │───▶│  Everything  │  │
│  │  (you define)   │    │  (you choose)   │    │  (you review)│  │
│  └─────────────────┘    └─────────────────┘    └──────────────┘  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                   GIT-STEER EXECUTION                             │
│                                                                   │
│  • Pulls code from GitHub at runtime (no local storage)          │
│  • Credentials in system Keychain (never in files)               │
│  • State in private repo (not on your machine)                   │
│  • All actions logged (append-only audit trail)                  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Credential Storage

### macOS Keychain

git-steer stores credentials in macOS Keychain:

| Item | Keychain Entry |
|------|----------------|
| GitHub App ID | `git-steer-app-id` |
| Installation ID | `git-steer-installation-id` |
| Private Key | `git-steer-private-key` |

**Benefits:**
- Encrypted at rest
- Protected by your login password
- Syncs via iCloud Keychain (if enabled)
- Accessible only to authorized apps

**To view stored credentials:**
1. Open Keychain Access
2. Search for "git-steer"
3. You'll see the entries (but not the values without authentication)

### Windows Credential Manager

On Windows, credentials are stored in Credential Manager:

1. Open Control Panel → Credential Manager
2. Look under "Generic Credentials"
3. Find entries starting with `git-steer`

### Linux

On Linux, git-steer uses the system's secret service (GNOME Keyring, KWallet, etc.):

```bash
# View stored secrets (if using secret-tool)
secret-tool search service git-steer
```

## GitHub App Permissions

### Principle of Least Privilege

git-steer requests permissions during setup, but **you can reduce them**:

| Permission | Default | Can Reduce To | Impact if Reduced |
|------------|---------|---------------|-------------------|
| Contents | Read & Write | Read-only | Can't modify branches |
| Administration | Read & Write | No access | Can't change settings, delete repos |
| Actions | Read & Write | Read-only | Can't trigger workflows or manage secrets |
| Security events | Read | — | Minimum needed for alerts |

### How to Reduce Permissions

1. Go to [github.com/settings/apps](https://github.com/settings/apps)
2. Find git-steer → **Edit**
3. Under **Permissions & events**, reduce as needed
4. Save changes
5. Re-authorize on each installation

### Permission Requirements by Tool

**Read-only tools** (work with minimal permissions):
- `repo_list`
- `branch_list`
- `security_alerts`, `security_digest`
- `actions_workflows`
- `config_show`, `steer_status`, `steer_logs`

**Write tools** (need corresponding write permissions):
- `repo_create`, `repo_archive`, `repo_delete`, `repo_settings`
- `branch_protect`, `branch_reap`
- `security_dismiss`
- `actions_trigger`, `actions_secrets`
- `config_add_repo`, `config_remove_repo`

## Repository Access Control

### Selective Access (Recommended)

Configure your GitHub App to access only specific repos:

1. Go to Settings → Applications → Installed GitHub Apps
2. Click **Configure** on git-steer
3. Select **Only select repositories**
4. Choose which repos to include

**This is the safest approach.** git-steer literally cannot see repos you don't add.

### All Repositories

Grants access to everything in your account/org. Use only if:
- You fully trust git-steer
- You want seamless management of all repos
- You're the only person with access to the account

### Managed vs. Accessible

There are two layers of access:

| Layer | What it controls | Where to change |
|-------|------------------|-----------------|
| **GitHub App access** | What git-steer *can see* | GitHub → Settings → Applications |
| **Managed repos** | What git-steer *actively manages* | `git-steer-state/config/managed-repos.yaml` |

You might give git-steer access to 50 repos but only actively manage 10.

## Audit Logging

Every action git-steer takes is logged to `git-steer-state/state/audit.jsonl`.

### Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "action": "branch_reap",
  "params": {
    "owner": "your-username",
    "repo": "my-repo",
    "daysStale": 30
  },
  "result": "success",
  "details": {
    "deleted": ["feature/old-branch", "fix/stale-fix"],
    "skipped": ["main", "develop"]
  }
}
```

### What Gets Logged

- Tool name and parameters
- Timestamp (UTC)
- Success/failure status
- Detailed results (what changed)
- Error messages (if failed)

### What Doesn't Get Logged

- Secrets or sensitive values
- Full file contents
- Credential access

### Reviewing Logs

**Via MCP:**
> "Show me git-steer logs from today"
> "What did git-steer do to my-repo?"

**Directly:**
Visit `github.com/YOUR-USERNAME/git-steer-state/blob/main/state/audit.jsonl`

**With jq (locally):**
```bash
git clone git@github.com:YOUR-USERNAME/git-steer-state.git
cat git-steer-state/state/audit.jsonl | jq 'select(.action == "repo_delete")'
```

## State Repository Security

The `git-steer-state` repo contains:
- Configuration (which repos, policies)
- Audit logs (all actions)
- Cache (rate limits, ETags)

### Keeping It Private

This repo is created as **private** by default. Keep it that way.

**To verify:**
1. Go to `github.com/YOUR-USERNAME/git-steer-state`
2. Check that "Private" badge shows next to the repo name

### Who Can Access

Only accounts with explicit access to the repo. By default, just you.

### Protecting the State Repo

Consider adding branch protection:
- Require PR reviews for config changes
- Prevent force pushes
- Enable signed commits

## Best Practices

### 1. Start Restrictive, Expand as Needed

- Begin with "Only select repositories"
- Add repos one at a time
- Use read-only permissions initially

### 2. Review Regularly

- Check audit logs monthly
- Review GitHub App permissions quarterly
- Remove repos you no longer manage

### 3. Use Confirmation for Destructive Actions

git-steer requires confirmation for:
- `repo_delete`
- `branch_reap` (when not dry run)

Never bypass these confirmations.

### 4. Keep Credentials Secure

- Don't share your Keychain
- Don't export credentials
- Rotate if compromised: `npx git-steer reset && npx git-steer init`

### 5. Monitor for Anomalies

- Unexpected repos being accessed
- Actions you didn't request
- Rate limit spikes

If you see anything suspicious:
1. Suspend the app immediately
2. Review audit logs
3. Reset credentials

### 6. Separate Personal and Org

Consider using separate GitHub Apps for:
- Personal repos
- Work organization repos
- Client projects

Each app has its own credentials and audit trail.

## Incident Response

### If Credentials Are Compromised

```bash
# 1. Reset immediately
npx git-steer reset

# 2. Revoke the GitHub App
# Go to github.com/settings/apps → git-steer → Delete

# 3. Review audit logs for unauthorized actions
# Check git-steer-state/state/audit.jsonl

# 4. Start fresh
npx git-steer init
```

### If Unauthorized Actions Occurred

1. Document what happened (timestamps, actions)
2. Review affected repos for changes
3. Revert any unauthorized modifications
4. Report to GitHub if malicious activity suspected

## Compliance Notes

### SOC 2 / ISO 27001

git-steer supports compliance requirements:
- **Access control:** Granular permissions
- **Audit trail:** Append-only logging
- **Credential management:** System keychain storage
- **Data residency:** State repo location is your choice

### GDPR

- No personal data is collected by git-steer
- All data stays in your GitHub account
- You control data retention via the state repo

---

**Questions about security?** [Open an issue](https://github.com/ry-ops/git-steer/issues) or email security concerns directly.
