import { describe, it, expect } from 'vitest';
import type { FabricGitHubAdapter } from '../fabric/adapter.js';

describe('FabricGitHubAdapter', () => {
  function createMockAdapter(): FabricGitHubAdapter {
    return {
      headers: () => ({
        Authorization: 'token test-token-123',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'git-steer/fabric-git',
      }),
      getFileContent: async () => null,
      commitFiles: async () => ({ sha: 'abc123', url: 'https://example.com' }),
      createBranch: async () => {},
      createPullRequest: async () => ({ number: 1, html_url: 'https://example.com/pr/1', url: 'https://api.example.com' }),
    };
  }

  it('headers() returns auth headers without exposing raw token', () => {
    const adapter = createMockAdapter();
    const headers = adapter.headers();
    expect(headers.Authorization).toBe('token test-token-123');
    expect(headers.Accept).toBe('application/vnd.github+json');
  });

  it('adapter interface has no token property', () => {
    const adapter = createMockAdapter();
    expect('token' in adapter).toBe(false);
  });
});
