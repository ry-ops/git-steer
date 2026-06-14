/**
 * verify-vex.mjs — validates the shipped OpenVEX logic (dist/web/routes/vex.js)
 * against ADR-004 C-004-003 / C-004-004. Pure functions, no Redis needed.
 */

import { validateVexInput, toOpenVex } from '../dist/web/routes/vex.js';

let ok = true;
const check = (name, pass) => { if (!pass) ok = false; console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}`); };

console.log('\n=== VEX input validation (ADR-004 C-004-003) ===');

// Rejections
check('rejects missing cve_id', validateVexInput({ status: 'fixed' }) !== null);
check('rejects invalid status', validateVexInput({ cve_id: 'CVE-1', status: 'bogus' }) !== null);
check('rejects not_affected WITHOUT justification',
  validateVexInput({ cve_id: 'CVE-1', status: 'not_affected' }) !== null);
check('rejects affected WITHOUT action_statement',
  validateVexInput({ cve_id: 'CVE-1', status: 'affected' }) !== null);
check('rejects non-OpenVEX justification (vulnerable_code_not_reachable)',
  validateVexInput({ cve_id: 'CVE-1', status: 'not_affected', justification: 'vulnerable_code_not_reachable' }) !== null);

// Acceptances
check('accepts not_affected WITH standard justification',
  validateVexInput({ cve_id: 'CVE-1', status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' }) === null);
check('accepts affected WITH action_statement',
  validateVexInput({ cve_id: 'CVE-1', status: 'affected', action_statement: 'No upstream fix; input is trusted/internal only.' }) === null);
check('accepts the new OpenVEX value vulnerable_code_not_present',
  validateVexInput({ cve_id: 'CVE-1', status: 'not_affected', justification: 'vulnerable_code_not_present' }) === null);

console.log('\n=== OpenVEX document shape (ADR-004 C-004-003 / C-004-004) ===');

const entries = [
  { cve_id: 'CVE-2025-0001', repo: 'ry-ops/demo', product_purl: 'pkg:npm/esbuild@0.25.12',
    status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path',
    impact_statement: 'NPM_CONFIG_REGISTRY not attacker-controlled in our CI.',
    created_at: '2026-06-14T00:00:00Z', updated_by: 'test' },
  { cve_id: 'CVE-2025-0002', repo: 'ry-ops/demo', product_purl: 'pkg:npm/left-pad@1.0.0',
    status: 'affected', action_statement: 'No fix available; accepted risk, tracked.',
    created_at: '2026-06-14T00:00:00Z', updated_by: 'test' },
];

const doc = toOpenVex('ry-ops/demo', entries, 'https://example/vex/1', '2026-06-14T00:00:00Z');
console.log(JSON.stringify(doc, null, 2));

check("@context is OpenVEX 0.2.0", doc['@context'] === 'https://openvex.dev/ns/v0.2.0');
check('has 2 statements', doc.statements.length === 2);
check('statement products carry PURL linkage', doc.statements[0].products[0]['@id'] === 'pkg:npm/esbuild@0.25.12');
check('not_affected statement carries justification', doc.statements[0].justification === 'vulnerable_code_not_in_execute_path');
check('affected statement carries action_statement', !!doc.statements[1].action_statement);

console.log(ok ? '\n✅ VEX is OpenVEX/ADR-004 compliant.' : '\n❌ VEX non-compliant.');
process.exit(ok ? 0 : 1);
