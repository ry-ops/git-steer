import { describe, it, expect } from 'vitest';

// Test the audit log rotation logic in isolation
describe('StateManager', () => {
  describe('audit log rotation', () => {
    const MAX_AUDIT_ENTRIES = 10000;

    it('keeps entries under limit', () => {
      const audit: any[] = [];
      for (let i = 0; i < 100; i++) {
        audit.push({ ts: new Date().toISOString(), action: 'test', result: 'success' });
      }

      // Simulate rotation logic
      if (audit.length > MAX_AUDIT_ENTRIES) {
        audit.splice(0, audit.length - MAX_AUDIT_ENTRIES);
      }

      expect(audit.length).toBe(100);
    });

    it('rotates when over limit', () => {
      const audit: any[] = [];
      for (let i = 0; i < MAX_AUDIT_ENTRIES + 500; i++) {
        audit.push({
          ts: new Date().toISOString(),
          action: 'test',
          result: 'success',
          index: i,
        });
      }

      // Simulate rotation logic
      if (audit.length > MAX_AUDIT_ENTRIES) {
        const rotated = audit.slice(-MAX_AUDIT_ENTRIES);
        expect(rotated.length).toBe(MAX_AUDIT_ENTRIES);
        // First entry should be index 500 (oldest kept)
        expect(rotated[0].index).toBe(500);
        // Last entry should be the newest
        expect(rotated[rotated.length - 1].index).toBe(MAX_AUDIT_ENTRIES + 499);
      }
    });
  });

  describe('managed repos', () => {
    it('prevents duplicate repos', () => {
      const managedRepos: Array<{ owner: string; name: string; policies: string[] }> = [];

      const addRepo = (repo: { owner: string; name: string; policies: string[] }) => {
        const existing = managedRepos.find(
          (r) => r.owner === repo.owner && r.name === repo.name
        );
        if (!existing) {
          managedRepos.push(repo);
        }
      };

      addRepo({ owner: 'ry-ops', name: 'git-steer', policies: [] });
      addRepo({ owner: 'ry-ops', name: 'git-steer', policies: ['different'] });
      addRepo({ owner: 'ry-ops', name: 'other-repo', policies: [] });

      expect(managedRepos.length).toBe(2);
      expect(managedRepos[0].name).toBe('git-steer');
      expect(managedRepos[1].name).toBe('other-repo');
    });

    it('removes repos correctly', () => {
      let managedRepos = [
        { owner: 'ry-ops', name: 'repo1', policies: [] },
        { owner: 'ry-ops', name: 'repo2', policies: [] },
        { owner: 'other', name: 'repo1', policies: [] },
      ];

      // Remove ry-ops/repo1
      managedRepos = managedRepos.filter(
        (r) => !(r.owner === 'ry-ops' && r.name === 'repo1')
      );

      expect(managedRepos.length).toBe(2);
      expect(managedRepos.find((r) => r.owner === 'ry-ops' && r.name === 'repo1')).toBeUndefined();
      expect(managedRepos.find((r) => r.owner === 'other' && r.name === 'repo1')).toBeDefined();
    });
  });
});
