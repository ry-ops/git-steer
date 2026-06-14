/**
 * Canonical OpenVEX vocabulary, validation, and serialization — shared by
 * every VEX writer so the two physical stores (web/Redis and the MCP
 * state layer's git-steer-state cache.json `_vex`) stay in agreement.
 *
 * Per ADR-004 C-004-003: status ∈ {not_affected, affected, fixed,
 * under_investigation}; `not_affected` REQUIRES a justification from the
 * OpenVEX vocabulary; `affected` REQUIRES an action_statement. Entries link
 * to an SBOM component by PURL (C-004-004).
 */

export type VexStatus = 'not_affected' | 'affected' | 'fixed' | 'under_investigation';

export type VexJustification =
  | 'component_not_present'
  | 'vulnerable_code_not_present'
  | 'vulnerable_code_not_in_execute_path'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'inline_mitigations_already_exist';

export const VEX_STATUSES: VexStatus[] = ['not_affected', 'affected', 'fixed', 'under_investigation'];
export const VEX_JUSTIFICATIONS: VexJustification[] = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
];

/** One canonical VEX entry shape used by all stores. */
export interface VexEntry {
  cve_id: string;
  repo: string;               // "owner/repo"
  product_purl?: string;      // SBOM component linkage (C-004-004)
  status: VexStatus;
  justification?: VexJustification;   // required when status === 'not_affected'
  action_statement?: string;          // required when status === 'affected'
  impact_statement?: string;          // optional detail for not_affected
  detail?: string;
  created_at: string;
  updated_by: string;
}

/** Map key for the git-steer-state `_vex` store (and any keyed map). */
export function vexId(repo: string, cveId: string): string {
  return `${repo}::${cveId}`;
}

export interface VexInput {
  cve_id?: string;
  status?: string;
  justification?: string;
  action_statement?: string;
  product_purl?: string;
}

/** Returns null if valid, else an error string. Enforces ADR-004 C-004-003. */
export function validateVexInput(body: VexInput): string | null {
  if (!body.cve_id) return 'cve_id is required';
  if (!body.status || !VEX_STATUSES.includes(body.status as VexStatus)) {
    return `status must be one of: ${VEX_STATUSES.join(', ')}`;
  }
  if (body.justification && !VEX_JUSTIFICATIONS.includes(body.justification as VexJustification)) {
    return `justification must be one of: ${VEX_JUSTIFICATIONS.join(', ')}`;
  }
  if (body.status === 'not_affected' && !body.justification) {
    return `status "not_affected" requires a justification (one of: ${VEX_JUSTIFICATIONS.join(', ')})`;
  }
  if (body.status === 'affected' && !body.action_statement) {
    return 'status "affected" requires an action_statement describing the mitigation or acceptance rationale';
  }
  return null;
}

export interface OpenVexDoc {
  '@context': string;
  '@id': string;
  author: string;
  timestamp: string;
  version: number;
  statements: Array<{
    vulnerability: { name: string };
    products: Array<{ '@id': string }>;
    status: VexStatus;
    justification?: VexJustification;
    impact_statement?: string;
    action_statement?: string;
  }>;
}

/** Serialize canonical VEX entries to an OpenVEX 0.2.0 document. */
export function toOpenVex(repo: string, entries: VexEntry[], id: string, timestamp: string): OpenVexDoc {
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': id,
    author: 'git-steer',
    timestamp,
    version: 1,
    statements: entries.map((e) => {
      const stmt: OpenVexDoc['statements'][number] = {
        vulnerability: { name: e.cve_id },
        products: [{ '@id': e.product_purl || `pkg:github/${repo}` }],
        status: e.status,
      };
      if (e.justification) stmt.justification = e.justification;
      if (e.impact_statement) stmt.impact_statement = e.impact_statement;
      if (e.action_statement) stmt.action_statement = e.action_statement;
      return stmt;
    }),
  };
}
