/**
 * verify-verdict.mjs — validates the ADR-005 verdict logic against the
 * doctrine truth table (C-005-002/003) + the SURFACE bump heuristic.
 * Build first: `npm run build`.
 */

import { aggregateVerdict, mayAutoMerge, surfaceForBump } from '../dist/core/verdict.js';

let ok = true;
const check = (name, pass) => { if (!pass) ok = false; console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}`); };
const D = (dimension, result) => ({ dimension, result });

console.log('\n=== Verdict aggregation (ADR-005 C-005-002/003) ===');

// NO-GO: any FAIL, regardless of passes
check('BUILD FAIL -> NO-GO',
  aggregateVerdict([D('BUILD', 'FAIL'), D('TEST', 'PASS')]) === 'NO-GO');
check('TEST FAIL -> NO-GO',
  aggregateVerdict([D('BUILD', 'PASS'), D('TEST', 'FAIL')]) === 'NO-GO');

// GO: no fail AND at least one real PASS
check('BUILD PASS + others N/A -> GO',
  aggregateVerdict([D('BUILD', 'PASS'), D('TEST', 'NOT_APPLICABLE'), D('SMOKE', 'NOT_APPLICABLE')]) === 'GO');
check('TEST PASS -> GO',
  aggregateVerdict([D('BUILD', 'NOT_APPLICABLE'), D('TEST', 'PASS')]) === 'GO');

// GO-UNVERIFIED: nothing failed, nothing executed (the false-GO defense)
check('all NOT_APPLICABLE -> GO-UNVERIFIED (green-by-absence)',
  aggregateVerdict([D('BUILD', 'NOT_APPLICABLE'), D('TEST', 'NOT_APPLICABLE'), D('SMOKE', 'NOT_APPLICABLE'), D('SURFACE', 'NOT_APPLICABLE')]) === 'GO-UNVERIFIED');
check('empty -> GO-UNVERIFIED',
  aggregateVerdict([]) === 'GO-UNVERIFIED');

console.log('\n=== Auto-merge gate (C-005-003) ===');
check('GO may auto-merge', mayAutoMerge('GO') === true);
check('GO-UNVERIFIED held', mayAutoMerge('GO-UNVERIFIED') === false);
check('NO-GO held', mayAutoMerge('NO-GO') === false);

console.log('\n=== SURFACE bump heuristic (C-005-002) ===');
check('major jump 1.x -> 2.x is FAIL',
  surfaceForBump('1.4.0', '2.0.0').result === 'FAIL');
check('patch 1.4.0 -> 1.4.3 is PASS',
  surfaceForBump('1.4.0', '1.4.3').result === 'PASS');
check('minor same-major 6.28.0 -> 6.30.4 (react-router) is PASS',
  surfaceForBump('6.28.0', '6.30.4').result === 'PASS');
check('0.x minor 0.25.0 -> 0.28.1 (esbuild) is FAIL (0.x minor = breaking)',
  surfaceForBump('0.25.0', '0.28.1').result === 'FAIL');
check('absent bump info -> NOT_APPLICABLE',
  surfaceForBump(undefined, undefined).result === 'NOT_APPLICABLE');

// End-to-end: our two git-steer dep overrides
console.log('\n=== Applied to git-steer overrides ===');
const esbuild = [D('BUILD', 'NOT_APPLICABLE'), D('TEST', 'NOT_APPLICABLE'), surfaceForBump('0.25.0', '0.28.1')];
const reactRouter = [D('BUILD', 'PASS'), surfaceForBump('6.28.0', '6.30.4')];
console.log(`  esbuild 0.25->0.28.1     => ${aggregateVerdict(esbuild)}  (expect NO-GO: held for human)`);
console.log(`  react-router 6.28->6.30.4 => ${aggregateVerdict(reactRouter)}  (expect GO)`);
check('esbuild override -> NO-GO', aggregateVerdict(esbuild) === 'NO-GO');
check('react-router override -> GO', aggregateVerdict(reactRouter) === 'GO');

console.log(ok ? '\n✅ Verdict logic matches ADR-005.' : '\n❌ Verdict logic mismatch.');
process.exit(ok ? 0 : 1);
