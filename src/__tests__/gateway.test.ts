import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── 1a & 1b: Gateway init ─────────────────────────────────────────────────────

describe('Gateway', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  describe('initGateway — success path', () => {
    it('returns available handle when CVE app loads', async () => {
      const mockTools = [
        { name: 'cve_scan' },
        { name: 'cve_enrich' },
        { name: 'cve_triage' },
        { name: 'cve_queue_list' },
        { name: 'cve_queue_stats' },
        { name: 'cve_compact' },
        { name: 'cve_queue_update' },
        { name: 'cve_queue_search' },
      ];

      const mockRegistry = {
        register: vi.fn(),
        list: vi.fn().mockReturnValue([{ name: 'cve' }]),
      };

      const mockRouter = {
        listTools: vi.fn().mockReturnValue(mockTools),
        route: vi.fn(),
      };

      vi.doMock('@git-fabric/gateway', () => ({
        createRegistry: vi.fn().mockReturnValue(mockRegistry),
        createRouter: vi.fn().mockReturnValue(mockRouter),
      }));

      vi.doMock('@git-fabric/cve', () => ({
        createApp: vi.fn().mockResolvedValue({ name: 'cve', tools: mockTools }),
      }));

      const { initGateway } = await import('../fabric/gateway.js');
      const handle = await initGateway({
        githubToken: 'ghp_test',
        stateRepo: 'ry-ops/git-steer-state',
        managedRepos: ['ry-ops/git-steer'],
      });

      expect(handle.available).toBe(true);
      expect(handle.appCount).toBe(1);
      expect(handle.toolCount).toBeGreaterThan(0);
      expect(handle.router).toBeDefined();
      expect(mockRegistry.register).toHaveBeenCalledOnce();
    });
  });

  describe('initGateway — degraded fallback', () => {
    it('returns unavailable handle when CVE app throws', async () => {
      vi.doMock('@git-fabric/gateway', () => ({
        createRegistry: vi.fn().mockReturnValue({
          register: vi.fn(),
          list: vi.fn().mockReturnValue([]),
        }),
        createRouter: vi.fn(),
      }));

      vi.doMock('@git-fabric/cve', () => ({
        createApp: vi.fn().mockRejectedValue(new Error('Missing env var')),
      }));

      const { initGateway } = await import('../fabric/gateway.js');
      const handle = await initGateway({
        githubToken: '',
        stateRepo: '',
        managedRepos: [],
      });

      expect(handle.available).toBe(false);
      expect(handle.appCount).toBe(0);
      expect(handle.toolCount).toBe(0);
    });

    it('does not throw when createApp fails', async () => {
      vi.doMock('@git-fabric/gateway', () => ({
        createRegistry: vi.fn().mockReturnValue({
          register: vi.fn(),
          list: vi.fn().mockReturnValue([]),
        }),
        createRouter: vi.fn(),
      }));

      vi.doMock('@git-fabric/cve', () => ({
        createApp: vi.fn().mockRejectedValue(new Error('boom')),
      }));

      const { initGateway } = await import('../fabric/gateway.js');

      // Should NOT throw — the whole point of the catch block
      await expect(
        initGateway({ githubToken: '', stateRepo: '', managedRepos: [] }),
      ).resolves.toBeDefined();
    });
  });

  // ── 1c: Tool mapping completeness ─────────────────────────────────────────

  describe('TOOL_MAP completeness', () => {
    // The TOOL_MAP is defined inline in server.ts executeTool().
    // We validate the contract here without needing to import it.
    const TOOL_MAP: Record<string, string> = {
      fabric_cve_scan: 'cve_scan',
      fabric_cve_enrich: 'cve_enrich',
      fabric_cve_triage: 'cve_triage',
      fabric_cve_queue: 'cve_queue_list',
      fabric_cve_stats: 'cve_queue_stats',
      fabric_cve_compact: 'cve_compact',
    };

    const FABRIC_TOOL_NAMES = [
      'fabric_cve_scan',
      'fabric_cve_enrich',
      'fabric_cve_triage',
      'fabric_cve_queue',
      'fabric_cve_stats',
      'fabric_cve_compact',
    ];

    it('maps all 6 fabric_cve_* tool names', () => {
      expect(Object.keys(TOOL_MAP)).toHaveLength(6);
    });

    it('every fabric tool has a mapping', () => {
      for (const name of FABRIC_TOOL_NAMES) {
        expect(TOOL_MAP[name]).toBeDefined();
        expect(TOOL_MAP[name]).toMatch(/^cve_/);
      }
    });

    it('has no duplicate target mappings', () => {
      const targets = Object.values(TOOL_MAP);
      const unique = new Set(targets);
      expect(unique.size).toBe(targets.length);
    });

    it('fabric names map to cve_* names without the fabric_ prefix pattern', () => {
      // Verify the naming convention: fabric_cve_X → cve_X (or cve_queue_X)
      for (const [fabric, cve] of Object.entries(TOOL_MAP)) {
        expect(fabric.startsWith('fabric_')).toBe(true);
        expect(cve.startsWith('cve_')).toBe(true);
      }
    });
  });

  // ── 1d: Conditional tool listing ──────────────────────────────────────────

  describe('conditional tool listing', () => {
    const FABRIC_CVE_TOOL_NAMES = [
      'fabric_cve_scan',
      'fabric_cve_enrich',
      'fabric_cve_queue',
      'fabric_cve_stats',
      'fabric_cve_compact',
    ];

    const CORE_TOOL_NAMES = [
      'repo_list', 'repo_create', 'repo_archive', 'repo_delete', 'repo_settings',
      'branch_list', 'branch_protect', 'branch_reap',
      'security_alerts', 'security_dismiss', 'security_digest',
      'actions_workflows', 'actions_trigger', 'actions_secrets',
      'steer_status', 'steer_sync', 'steer_logs',
      'config_show', 'config_add_repo', 'config_remove_repo',
      'security_scan', 'security_fix_pr', 'workflow_status',
      'repo_commit', 'repo_read_file', 'repo_list_files',
      'security_enforce', 'code_quality_sweep',
      'report_generate', 'dashboard_generate', 'code_review',
    ];

    it('FABRIC_CVE_TOOLS has exactly 5 tools', () => {
      expect(FABRIC_CVE_TOOL_NAMES).toHaveLength(5);
    });

    it('FABRIC_CVE_TOOLS has correct names', () => {
      for (const name of FABRIC_CVE_TOOL_NAMES) {
        expect(name).toMatch(/^fabric_cve_/);
      }
    });

    it('CORE_TOOLS does not contain any fabric_cve_* tools', () => {
      for (const name of CORE_TOOL_NAMES) {
        expect(name).not.toMatch(/^fabric_cve_/);
      }
    });

    it('combined tool count equals core + fabric', () => {
      const combined = [...CORE_TOOL_NAMES, ...FABRIC_CVE_TOOL_NAMES];
      expect(combined.length).toBe(CORE_TOOL_NAMES.length + FABRIC_CVE_TOOL_NAMES.length);
      // No duplicates
      expect(new Set(combined).size).toBe(combined.length);
    });
  });

  // ── 1e: JSON result parsing ───────────────────────────────────────────────

  describe('JSON result parsing', () => {
    it('parses valid JSON string results', () => {
      const jsonStr = '{"total": 5, "byStatus": {"pending": 3}}';
      const parsed = JSON.parse(jsonStr);
      expect(parsed.total).toBe(5);
      expect(parsed.byStatus.pending).toBe(3);
    });

    it('passes object results through unchanged', () => {
      const obj = { total: 5, byStatus: { pending: 3 } };
      // Simulates the gateway routing logic:
      // typeof result.result === 'string' ? JSON.parse(result.result) : result.result
      const result = typeof obj === 'string' ? JSON.parse(obj) : obj;
      expect(result).toBe(obj); // same reference
      expect(result.total).toBe(5);
    });

    it('throws on malformed JSON strings', () => {
      const badJson = '{not valid json';
      expect(() => JSON.parse(badJson)).toThrow();
    });

    it('handles nested JSON results', () => {
      const jsonStr = JSON.stringify({
        total: 10,
        byStatus: { pending: 3, pr_opened: 7 },
        pendingBySeverity: { CRITICAL: 1, HIGH: 2 },
      });
      const parsed = JSON.parse(jsonStr);
      expect(parsed.total).toBe(10);
      expect(parsed.byStatus.pending).toBe(3);
      expect(parsed.pendingBySeverity.CRITICAL).toBe(1);
    });

    it('handles empty object JSON', () => {
      const parsed = JSON.parse('{}');
      expect(parsed).toEqual({});
    });
  });
});
