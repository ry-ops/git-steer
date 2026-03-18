import { describe, it, expect } from 'vitest';
import { DESTRUCTIVE_TOOLS, DRY_RUN_DEFAULT_TOOLS } from '../mcp/permissions.js';

describe('permissions', () => {
  describe('DESTRUCTIVE_TOOLS', () => {
    it('contains repo_delete', () => {
      expect(DESTRUCTIVE_TOOLS.has('repo_delete')).toBe(true);
    });

    it('contains branch_reap', () => {
      expect(DESTRUCTIVE_TOOLS.has('branch_reap')).toBe(true);
    });

    it('contains cert_renew', () => {
      expect(DESTRUCTIVE_TOOLS.has('cert_renew')).toBe(true);
    });

    it('does not contain read-only tools', () => {
      expect(DESTRUCTIVE_TOOLS.has('repo_list')).toBe(false);
      expect(DESTRUCTIVE_TOOLS.has('steer_status')).toBe(false);
    });
  });

  describe('DRY_RUN_DEFAULT_TOOLS', () => {
    it('contains security_sweep', () => {
      expect(DRY_RUN_DEFAULT_TOOLS.has('security_sweep')).toBe(true);
    });

    it('contains oomkill_remediate', () => {
      expect(DRY_RUN_DEFAULT_TOOLS.has('oomkill_remediate')).toBe(true);
    });
  });
});
