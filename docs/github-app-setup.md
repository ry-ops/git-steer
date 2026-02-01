# GitHub App Setup

The GitHub App is your **companion app** for git-steer. It's how git-steer authenticates with GitHub and accesses your repositories.

**You have complete control** over what this app can do and which repositories it can access. This guide explains how to configure it.

## Understanding the GitHub App

When you run `npx git-steer init`, git-steer creates a GitHub App registered to your account. This app:

- Acts as git-steer's identity when talking to the GitHub API
- Has permissions you define during setup
- Can only access repositories you explicitly allow
- Can be suspended, modified, or deleted at any time

**The app lives in your GitHub account.** You own it. You control it.

## Accessing Your GitHub App Settings

After installation, manage your app at:

```
https://github.com/settings/installations
```

Or navigate manually:
1. Go to [github.com](https://github.com)
2. Click your profile picture → **Settings**
3. Scroll to **Integrations** → **Applications**
4. Click **Installed GitHub Apps**
5. Find **git-steer** and click **Configure**

## Repository Access Control

This is where you decide how much access git-steer has.

### Option 1: All Repositories

Gives git-steer access to every repo in your account, including future repos.

**Best for:**
- Personal accounts where you want full automation
- When you trust git-steer to manage everything

**To enable:**
1. Go to your git-steer app settings
2. Under "Repository access," select **All repositories**
3. Click **Save**

### Option 2: Only Select Repositories (Recommended)

Gives git-steer access to only the repos you choose.

**Best for:**
- Most users
- When you want granular control
- Organizations with sensitive repos
- Testing git-steer before going all-in

**To enable:**
1. Go to your git-steer app settings
2. Under "Repository access," select **Only select repositories**
3. Use the dropdown to add specific repos
4. Click **Save**

**You can change this anytime.** Add or remove repos whenever you want.

### Permission Levels Explained

The GitHub App requests certain permissions during creation. Here's what they mean:

| Permission | Level | What It Allows |
|------------|-------|----------------|
| **Repository - Contents** | Read & Write | Read/write files, branches, commits |
| **Repository - Metadata** | Read | View repo info (name, description, visibility) |
| **Repository - Administration** | Read & Write | Change repo settings, delete repos |
| **Repository - Actions** | Read & Write | Manage workflows, secrets, runs |
| **Repository - Security events** | Read | View Dependabot and code scanning alerts |
| **Organization - Members** | Read | List org members (for org installs) |

### Reducing Permissions

If you want a **read-only** setup:

1. Go to [github.com/settings/apps](https://github.com/settings/apps)
2. Find your git-steer app → click **Edit**
3. Under **Permissions & events**, change:
   - Repository - Contents → **Read-only**
   - Repository - Administration → **No access**
   - Repository - Actions → **Read-only**
4. Click **Save changes**

**Note:** Some git-steer tools won't work with reduced permissions. See the [Usage Guide](usage-guide.md) for which tools need which permissions.

## Suspending the App

Need to temporarily disable git-steer without uninstalling?

1. Go to your git-steer app settings
2. Scroll to the bottom
3. Click **Suspend**

The app keeps its configuration but can't access any repos until you click **Unsuspend**.

## Uninstalling the App

To completely remove git-steer's access:

1. Go to your git-steer app settings
2. Scroll to the bottom
3. Click **Uninstall**

This removes all access immediately. Your `git-steer-state` repo remains (you can delete it manually if desired).

To also remove local credentials:

```bash
npx git-steer reset
```

## Reinstalling or Reconfiguring

### Changing Permissions

1. Go to [github.com/settings/apps](https://github.com/settings/apps)
2. Find git-steer → **Edit**
3. Modify permissions under **Permissions & events**
4. Save changes
5. Each account where the app is installed will need to approve new permissions

### Starting Fresh

```bash
# Remove everything
npx git-steer reset

# Reinitialize
npx git-steer init
```

## Organization Installations

If you want to use git-steer with an organization:

1. You must be an **organization owner** (or have permission to install apps)
2. During `npx git-steer init`, select the organization instead of your personal account
3. The app will only have access to repos you select within that org

**For multiple orgs:** Run `npx git-steer init` multiple times, selecting a different org each time.

## Security Best Practices

1. **Start with "Only select repositories"** - Add repos as needed rather than granting all access upfront

2. **Review permissions periodically** - Check what repos git-steer can access at `github.com/settings/installations`

3. **Use read-only for sensitive repos** - If you just want to view alerts or list branches, reduce permissions

4. **Check the audit log** - git-steer logs all actions to your `git-steer-state` repo

5. **Suspend when not in use** - If you're not actively using git-steer, suspend the app

## Troubleshooting

### "App not found" Error

Your app credentials may be corrupted. Run:

```bash
npx git-steer reset
npx git-steer init
```

### "Insufficient permissions" Error

The operation requires permissions your app doesn't have. Either:
- Add the required permission (see [Reducing Permissions](#reducing-permissions) above)
- Or accept that this operation isn't available with your current setup

### Can't See Organization

Make sure you're an org owner. If your org has app installation restrictions, contact your org admin.

---

**Next:** [Configure git-steer](configuration.md) to set up policies and managed repos.
