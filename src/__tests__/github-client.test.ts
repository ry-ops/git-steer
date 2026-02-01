import { describe, it, expect } from 'vitest';
import { GitHubClient } from '../github/client.js';

describe('GitHubClient', () => {
  describe('constructor validation', () => {
    it('throws on invalid installationId - empty string', () => {
      expect(() => {
        new GitHubClient({
          appId: '12345',
          privateKey: 'fake-key',
          installationId: '',
        });
      }).toThrow('Invalid installation ID');
    });

    it('throws on invalid installationId - non-numeric', () => {
      expect(() => {
        new GitHubClient({
          appId: '12345',
          privateKey: 'fake-key',
          installationId: 'abc',
        });
      }).toThrow('Invalid installation ID');
    });

    it('throws on invalid installationId - negative', () => {
      expect(() => {
        new GitHubClient({
          appId: '12345',
          privateKey: 'fake-key',
          installationId: '-1',
        });
      }).toThrow('Invalid installation ID');
    });

    it('throws on invalid installationId - zero', () => {
      expect(() => {
        new GitHubClient({
          appId: '12345',
          privateKey: 'fake-key',
          installationId: '0',
        });
      }).toThrow('Invalid installation ID');
    });

    it('accepts valid installationId', () => {
      // This will fail on authenticate() but constructor should pass
      const client = new GitHubClient({
        appId: '12345',
        privateKey: 'fake-key',
        installationId: '12345678',
      });
      expect(client).toBeDefined();
      expect(client.isAuthenticated()).toBe(false);
    });
  });
});
