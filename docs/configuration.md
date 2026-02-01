# Configuration

git-steer stores all configuration in your private `git-steer-state` repository. No config files on your machine.

## State Repository Structure

After running `npx git-steer init`, you'll have a repo at `github.com/YOUR-USERNAME/git-steer-state`:

```
git-steer-state/
├── config/
│   ├── managed-repos.yaml    # Which repos git-steer actively manages
│   ├── policies.yaml         # Branch protection templates
│   └── schedules.yaml        # Scheduled job definitions
├── state/
│   ├── audit.jsonl           # Action log (append-only)
│   ├── jobs.jsonl            # Job history
│   └── cache.json            # Rate limits, ETags
└── .github/workflows/
    └── heartbeat.yml         # Scheduled job triggers
```

## Managed Repos

The `managed-repos.yaml` file defines which repos git-steer actively monitors and can modify.

**Important:** This is different from GitHub App repository access:
- **GitHub App access** = which repos git-steer *can* see
- **Managed repos** = which repos git-steer *actively* manages

### Example Configuration

```yaml
# config/managed-repos.yaml
repos:
  # Manage all repos in your account
  - owner: your-username
    name: "*"
    policies:
      - standard-protection
      - security-alerts

  # Or specify individual repos
  - owner: your-username
    name: my-api
    policies:
      - strict-protection
      - no-force-push
  
  - owner: your-username
    name: my-frontend
    policies:
      - standard-protection

  # Organization repos
  - owner: my-org
    name: shared-lib
    policies:
      - org-standard
```

### Adding Repos via MCP

You can manage repos through natural language:

**You:** "Add my-new-repo to managed repos with standard protection"

**Claude:** *[calls config_add_repo]*

Or use the tool directly:

```
Tool: config_add_repo
Params: { owner: "your-username", name: "my-new-repo", policies: ["standard-protection"] }
```

### Removing Repos

**You:** "Remove my-old-repo from managed repos"

**Claude:** *[calls config_remove_repo]*

## Policies

Policies are reusable templates for branch protection rules and other settings.

### Example Policies

```yaml
# config/policies.yaml
policies:
  # Basic protection for personal projects
  standard-protection:
    branches:
      - pattern: main
        protection:
          required_reviews: 0
          dismiss_stale_reviews: false
          require_status_checks: false

  # Strict protection for production code
  strict-protection:
    branches:
      - pattern: main
        protection:
          required_reviews: 2
          dismiss_stale_reviews: true
          require_code_owner_reviews: true
          require_status_checks: true
          required_checks:
            - ci/build
            - ci/test
      - pattern: release/*
        protection:
          required_reviews: 1

  # Prevent force pushes on all branches
  no-force-push:
    branches:
      - pattern: "*"
        protection:
          allow_force_pushes: false
          allow_deletions: false

  # Security-focused policy
  security-alerts:
    alerts:
      dependabot: true
      code_scanning: true
      secret_scanning: true
```

### Applying Policies via MCP

**You:** "Apply strict protection to the main branch of my-api"

**Claude:** *[calls branch_protect with policy: "strict-protection"]*

### Custom Rules

For one-off protection without creating a policy:

```
Tool: branch_protect
Params: {
  owner: "your-username",
  repo: "my-repo",
  branch: "main",
  policy: "custom",
  customRules: {
    requiredReviews: 1,
    requireStatusChecks: ["ci/test"],
    dismissStaleReviews: true
  }
}
```

## Schedules

Define scheduled jobs that run via GitHub Actions.

### Example Schedules

```yaml
# config/schedules.yaml
schedules:
  # Clean up stale branches every Sunday
  weekly-branch-cleanup:
    cron: "0 0 * * 0"
    action: branch_reap
    params:
      daysStale: 30
      exclude:
        - main
        - develop
    repos: "*"  # All managed repos

  # Daily security digest
  daily-security-check:
    cron: "0 9 * * *"
    action: security_digest
    params:
      severity: high
    notify:
      slack: "#security-alerts"

  # Archive inactive repos monthly
  monthly-archive-check:
    cron: "0 0 1 * *"
    action: repo_archive
    params:
      daysInactive: 180
      dryRun: true  # Report only, don't actually archive
```

### How Schedules Work

1. git-steer creates a `heartbeat.yml` workflow in your state repo
2. The workflow triggers at the defined cron times
3. It sends a webhook to trigger the specified action
4. Results are logged to `state/jobs.jsonl`

## Viewing Current Configuration

### Via MCP

**You:** "Show me my current git-steer config"

**Claude:** *[calls config_show]*

### Specific Sections

```
Tool: config_show
Params: { section: "repos" }     # Just managed repos
Params: { section: "policies" }  # Just policies
Params: { section: "schedules" } # Just schedules
Params: { section: "all" }       # Everything
```

### Directly on GitHub

Visit `github.com/YOUR-USERNAME/git-steer-state` and browse the `config/` directory.

## Editing Configuration Manually

You can edit the YAML files directly:

1. Clone your state repo: `git clone git@github.com:YOUR-USERNAME/git-steer-state.git`
2. Edit files in `config/`
3. Commit and push
4. Run `npx git-steer sync` to reload

Or edit directly on GitHub and run sync.

## Syncing State

Force git-steer to reload configuration from GitHub:

```bash
npx git-steer sync
```

Or via MCP:

**You:** "Sync git-steer state"

**Claude:** *[calls steer_sync]*

## Configuration Best Practices

1. **Start with wildcards, refine later** - Use `name: "*"` initially, then add specific repos with custom policies

2. **Use policies for consistency** - Don't apply one-off custom rules everywhere; create named policies

3. **Enable dry-run for destructive schedules** - Test with `dryRun: true` before enabling actual archival or deletion

4. **Review the audit log** - Check `state/audit.jsonl` periodically to see what git-steer has done

5. **Version your config** - The state repo has full git history; use it to track changes

---

**Next:** [Learn how to use git-steer](usage-guide.md) with MCP tools and example prompts.
