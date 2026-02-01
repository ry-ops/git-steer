# Troubleshooting

Common issues and how to fix them.

## Installation Issues

### "Command not found: npx"

Node.js isn't installed or isn't in your PATH.

**Fix:**
1. Install Node.js 18+ from [nodejs.org](https://nodejs.org/)
2. Restart your terminal
3. Verify: `node --version` and `npx --version`

### "Permission denied" during init

Your terminal doesn't have permission to access Keychain (macOS) or Credential Manager (Windows).

**Fix (macOS):**
1. Go to System Preferences → Security & Privacy → Privacy → Accessibility
2. Add your terminal app (Terminal, iTerm, etc.)
3. Restart terminal and try again

**Fix (Windows):**
Run your terminal as Administrator for the initial setup.

### GitHub App creation fails

Usually a network or authentication issue.

**Fix:**
1. Make sure you're logged into GitHub in your browser
2. Check your internet connection
3. Try again: `npx git-steer init`

If it still fails, create the app manually:
1. Go to [github.com/settings/apps/new](https://github.com/settings/apps/new)
2. Follow the prompts in the git-steer README
3. Run `npx git-steer init --manual` with your app credentials

## Connection Issues

### "Failed to connect to GitHub API"

**Possible causes:**
- No internet connection
- GitHub is down
- Firewall blocking requests

**Fix:**
1. Check [githubstatus.com](https://www.githubstatus.com/)
2. Test connectivity: `curl -I https://api.github.com`
3. If behind a corporate firewall, you may need to configure proxy settings

### "Rate limit exceeded"

You've hit GitHub's API rate limit (5,000 requests/hour for authenticated apps).

**Fix:**
1. Wait for the rate limit to reset (check `npx git-steer status`)
2. Reduce the frequency of operations
3. For heavy usage, consider multiple GitHub Apps

**Prevention:**
- Use `steer_status` to monitor rate limits
- Batch operations when possible
- Enable caching in your state repo

### "Token expired" or "Bad credentials"

Your GitHub App credentials are invalid or expired.

**Fix:**
```bash
npx git-steer reset
npx git-steer init
```

## Permission Issues

### "Resource not accessible by integration"

The GitHub App doesn't have permission for this operation.

**Check required permissions:**
1. Look up the tool in the [Usage Guide](usage-guide.md#mcp-tools-reference)
2. Go to [github.com/settings/apps](https://github.com/settings/apps)
3. Edit your git-steer app
4. Add the required permission
5. Re-authorize the app where it's installed

### "Repository not found"

Either the repo doesn't exist, or your app doesn't have access.

**Fix:**
1. Verify the repo exists: `https://github.com/owner/repo`
2. Check app access: Settings → Applications → Installed GitHub Apps → git-steer → Configure
3. Add the repo to "Only select repositories" if using selective access

### Can't access organization repos

Organization apps require owner approval.

**Fix:**
1. Ask an org owner to approve the app
2. Or install the app directly at the org level (requires owner permissions)

## Claude Desktop Issues

### git-steer not showing in Claude

The MCP server isn't configured correctly.

**Fix:**
1. Check config file exists:
   - macOS: `~/.config/claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. Verify JSON syntax:
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

3. **Fully restart Claude Desktop** (quit and reopen, not just close window)

### "MCP server failed to start"

git-steer crashed during startup.

**Fix:**
1. Test manually: `npx git-steer` (should start without errors)
2. Check for Node.js version issues: `node --version` (need 18+)
3. Clear npm cache: `npm cache clean --force`
4. Reinstall: `npm uninstall -g git-steer && npm install -g git-steer`

### Tools timeout or hang

Usually a network issue or GitHub API slowness.

**Fix:**
1. Check your internet connection
2. Check [githubstatus.com](https://www.githubstatus.com/)
3. Try a simpler operation first: "git-steer status"

## State Repository Issues

### "State repo not found"

The `git-steer-state` repo was deleted or renamed.

**Fix:**
```bash
npx git-steer reset
npx git-steer init
```

This creates a fresh state repo.

### State out of sync

Changes made directly to the state repo aren't reflected.

**Fix:**
```bash
npx git-steer sync
```

Or via MCP: "Sync git-steer state"

### Corrupted state

Invalid YAML or JSON in state files.

**Fix:**
1. Go to `github.com/YOUR-USERNAME/git-steer-state`
2. Check recent commits for the breaking change
3. Revert or fix the invalid file
4. Run `npx git-steer sync`

## Tool-Specific Issues

### branch_reap not deleting branches

**Possible causes:**
- Branches are protected
- Branches are in the exclude list
- `dryRun: true` is set

**Fix:**
1. Check protection: "Show branch protection for my-repo"
2. Check exclude list in your config
3. Explicitly set `dryRun: false`

### repo_delete not working

Requires typing the exact repo name to confirm.

**Fix:**
Respond with exactly the repo name when prompted. Example:
> **Claude:** "Type 'my-repo' to confirm deletion"
> **You:** "my-repo" (not "yes" or "confirm")

### security_alerts returns empty

**Possible causes:**
- No alerts exist (good news!)
- Security features not enabled on the repo
- Insufficient permissions

**Fix:**
1. Check if Dependabot is enabled on the repo
2. Verify your app has "Security events: Read" permission
3. Try `security_digest` for a broader view

## Performance Issues

### Operations are slow

**Possible causes:**
- Large number of repos
- GitHub API latency
- Rate limiting

**Fix:**
1. Check rate limit status: `npx git-steer status`
2. Use filters to reduce scope: "List only repos updated this month"
3. Enable caching in state repo

### High memory usage

git-steer caches data in memory during operation.

**Fix:**
1. Restart git-steer periodically for long sessions
2. Reduce the number of managed repos
3. Use selective operations instead of wildcard queries

## Reset Everything

When all else fails:

```bash
# Remove local credentials and config
npx git-steer reset

# Delete state repo manually on GitHub
# (visit github.com/YOUR-USERNAME/git-steer-state → Settings → Delete)

# Start fresh
npx git-steer init
```

## Getting Help

If you're still stuck:

1. **Check existing issues:** [github.com/ry-ops/git-steer/issues](https://github.com/ry-ops/git-steer/issues)

2. **Open a new issue** with:
   - What you were trying to do
   - The exact error message
   - Output of `npx git-steer status`
   - Your OS and Node.js version

3. **Join the discussion:** [github.com/ry-ops/git-steer/discussions](https://github.com/ry-ops/git-steer/discussions)

---

**Still having trouble?** [Open an issue](https://github.com/ry-ops/git-steer/issues/new) and we'll help you out.
