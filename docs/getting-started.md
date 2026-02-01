# Getting Started

This guide walks you through forking, starring, and installing git-steer.

## Prerequisites

Before you begin, make sure you have:

- **Node.js 18+** - [Download here](https://nodejs.org/)
- **A GitHub account** - [Sign up](https://github.com/signup)
- **macOS** (for Keychain support) or **Windows/Linux** (with alternative credential storage)
- **Claude Desktop** - [Download here](https://claude.ai/download)

## Fork the Repository

Forking creates your own copy of git-steer, letting you customize it and stay updated with upstream changes.

### How to Fork

1. Go to [github.com/ry-ops/git-steer](https://github.com/ry-ops/git-steer)
2. Click the **Fork** button in the top-right corner
3. Select your account as the destination
4. (Optional) Uncheck "Copy the `main` branch only" if you want all branches
5. Click **Create fork**

You now have `github.com/YOUR-USERNAME/git-steer`.

### Keeping Your Fork Updated

```bash
# Add the original repo as upstream (one-time setup)
git remote add upstream https://github.com/ry-ops/git-steer.git

# Fetch and merge updates
git fetch upstream
git merge upstream/main
```

## Star the Repository

Starring helps you find the repo later and shows support for the project.

1. Go to [github.com/ry-ops/git-steer](https://github.com/ry-ops/git-steer)
2. Click the **⭐ Star** button in the top-right corner

That's it. You'll now see git-steer in your starred repos at [github.com/stars](https://github.com/stars).

## Installation

### Quick Install (Recommended)

Run the initialization wizard:

```bash
npx git-steer init
```

This will:
1. Create a GitHub App with the permissions you specify
2. Install the app to your account
3. Create a private `git-steer-state` repo for configuration and logs
4. Store credentials securely in your system's keychain

### What Gets Installed Where

| Item | Location | Purpose |
|------|----------|---------|
| GitHub App credentials | macOS Keychain / Windows Credential Manager | Authentication |
| Claude Desktop config | `~/.config/claude/claude_desktop_config.json` | MCP server registration |
| State repository | `github.com/YOUR-USERNAME/git-steer-state` | Config, policies, audit logs |

**That's it.** No dotfiles. No `~/.git-steer`. No config files on your machine.

### Manual Installation

If you prefer more control:

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/git-steer.git
cd git-steer

# Install dependencies
npm install

# Build
npm run build

# Run init
npm run init
```

## Verify Installation

Check that everything is working:

```bash
npx git-steer status
```

You should see:
- ✅ GitHub App credentials found
- ✅ State repository accessible
- ✅ Rate limits healthy

## Next Steps

Your git-steer installation is ready. Now:

1. **[Set up your GitHub App](github-app-setup.md)** - Configure permissions and repo access
2. **[Configure git-steer](configuration.md)** - Set up policies and managed repos
3. **[Start using it](usage-guide.md)** - Learn the MCP tools and example prompts

---

**Having trouble?** Check the [Troubleshooting](troubleshooting.md) guide or [open an issue](https://github.com/ry-ops/git-steer/issues).
