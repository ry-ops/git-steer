# 🚜 git-steer Documentation

git-steer looks after a fleet of GitHub repositories, and runs only on GitHub. The current design is [ADR-008](../adr/ADR-008.yaml): GitHub-native protection (Layer 0), each repo healing itself (Layer 1), and a read-only fleet view (Layer 2). The [README](../README.md) has the overview.

## Documentation

| Guide | Description |
|-------|-------------|
| [GitHub App Setup](github-app-setup.md) | The git-steer GitHub App, whose single-repo tokens are used by workflows such as `lockfiles.yml` |
| [Configuration](configuration.md) | The `git-steer-state` repo and `managed-repos.yaml` |
| [Autonomy Rollout](autonomy-rollout.md) | Earlier per-repo Dependabot auto-merge design; the starting point for `heal.yml` |
| [Auto-Scan Setup](auto-scan-setup.md) | Retired |

The local install, Claude Desktop and Keychain guides were removed with the MCP server and CLI (ADR-008 C-008-001: git-steer is never run on a workstation).

## Quick Links

- **Repository**: [github.com/ry-ops/git-steer](https://github.com/ry-ops/git-steer)
- **Issues**: [Report bugs or request features](https://github.com/ry-ops/git-steer/issues)
- **Author**: [ry-ops](https://github.com/ry-ops) • [Blog](https://ry-ops.dev)

## License

MIT - see [LICENSE](https://github.com/ry-ops/git-steer/blob/main/LICENSE)
