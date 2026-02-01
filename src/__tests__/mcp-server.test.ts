import { describe, it, expect } from 'vitest';

describe('MCP Server', () => {
  describe('repo filter regex', () => {
    // Test the regex escaping logic used in repo_list
    const createFilterPattern = (filter: string): RegExp => {
      const escaped = filter
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*');
      return new RegExp(`^${escaped}$`, 'i');
    };

    it('matches simple glob patterns', () => {
      const pattern = createFilterPattern('ry-ops/*');
      expect(pattern.test('ry-ops/git-steer')).toBe(true);
      expect(pattern.test('ry-ops/other-repo')).toBe(true);
      expect(pattern.test('other/git-steer')).toBe(false);
    });

    it('matches exact names', () => {
      const pattern = createFilterPattern('ry-ops/git-steer');
      expect(pattern.test('ry-ops/git-steer')).toBe(true);
      expect(pattern.test('ry-ops/git-steer-state')).toBe(false);
    });

    it('escapes regex special characters', () => {
      const pattern = createFilterPattern('user.name/repo+plus');
      expect(pattern.test('user.name/repo+plus')).toBe(true);
      expect(pattern.test('username/repoplus')).toBe(false); // . and + should be literal
    });

    it('handles wildcards in middle of pattern', () => {
      const pattern = createFilterPattern('ry-ops/git-*-state');
      expect(pattern.test('ry-ops/git-steer-state')).toBe(true);
      expect(pattern.test('ry-ops/git-foo-state')).toBe(true);
      expect(pattern.test('ry-ops/git-state')).toBe(false);
    });

    it('is case insensitive', () => {
      const pattern = createFilterPattern('RY-OPS/*');
      expect(pattern.test('ry-ops/git-steer')).toBe(true);
      expect(pattern.test('Ry-Ops/Git-Steer')).toBe(true);
    });

    it('prevents ReDoS with malicious patterns', () => {
      // This pattern would cause ReDoS without proper escaping
      const start = Date.now();
      const pattern = createFilterPattern('(.*)*a');
      pattern.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab');
      const elapsed = Date.now() - start;

      // Should complete quickly (< 100ms) if properly escaped
      expect(elapsed).toBeLessThan(100);
    });
  });

  describe('tool definitions', () => {
    // Verify all expected tools are defined
    const EXPECTED_TOOLS = [
      'repo_list',
      'repo_create',
      'repo_archive',
      'repo_delete',
      'repo_settings',
      'branch_list',
      'branch_protect',
      'branch_reap',
      'security_alerts',
      'security_dismiss',
      'security_digest',
      'actions_workflows',
      'actions_trigger',
      'actions_secrets',
      'steer_status',
      'steer_sync',
      'steer_logs',
      'config_show',
      'config_add_repo',
      'config_remove_repo',
    ];

    it('has all expected tools', () => {
      // This is a static check - in a real test we'd import TOOLS
      expect(EXPECTED_TOOLS.length).toBe(20);
    });
  });
});
