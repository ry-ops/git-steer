# Git-Steer Project

Git-Steer is an MCP server for GitHub repository management. It provides tools for repo settings, branch management, PR workflows, and security scanning.

## Project Structure

- `src/mcp/server.ts` - MCP server with all tool definitions
- `src/github/client.ts` - GitHub API client
- `src/core/` - Core functionality (keychain, setup, etc.)
- `bin/cli.js` - CLI entry point

## Development

```bash
npm run build    # Compile TypeScript
npm run dev      # Development mode
npm test         # Run tests
```

## Aiana Integration

Aiana is available as an MCP server for conversation memory. Use her proactively:

- `memory_recall` - Get context about git-steer from past sessions
- `memory_search` - Search past conversations for relevant info
- `memory_add` - Save important decisions or patterns

When working on git-steer, check Aiana for:
- Previous discussions about architecture decisions
- Patterns established in past sessions
- User preferences for this project
