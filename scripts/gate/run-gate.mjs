/**
 * run-gate.mjs — ADR-005 functional-integrity gate, monorepo-aware (ADR-007 Move B).
 *
 * The original gate (inlined in security-fix-worker.yml and mirrored in
 * verify-functional-form.yml) only probed the repo ROOT for a manifest. Any
 * repo whose manifests live in subdirectories (frontend/, backend/, packages/*,
 * python-sdk/, …) therefore exercised NOTHING — every dimension came back
 * NOT_APPLICABLE and the verdict was forced to GO-UNVERIFIED, so the fix was
 * held for a human forever. That was the dominant reason the fleet's
 * remediation loop stalled (commit-relay, DriveIQ, blog, …).
 *
 * This gate DISCOVERS every package in the tree (npm / go / python), runs
 * BUILD / TEST / SMOKE per package in its own ecosystem, and aggregates each
 * dimension across all packages:
 *   - dimension is FAIL            if ANY package failed it
 *   - else PASS                    if ANY package actually passed it
 *   - else NOT_APPLICABLE          (nothing executed — green-by-absence)
 *
 * Final verdict aggregation mirrors src/core/verdict.ts (the canonical,
 * unit-tested source): any FAIL -> NO-GO; else any PASS -> GO; else
 * GO-UNVERIFIED. Only GO auto-merges (C-005-003).
 *
 * Usage: node run-gate.mjs <targetDir> [--from <ver>] [--to <ver>]
 * Emits JSON to stdout and, if GITHUB_OUTPUT is set, writes
 * `verdict=` / `dimensions=` / `packages=` lines for the workflow to consume.
 */

import { execSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync, appendFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', '.github', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__']);
const MAX_DEPTH = 4; // deep enough for packages/*/svc, shallow enough to stay fast

// ── package discovery ────────────────────────────────────────────────
function discover(root) {
  const pkgs = [];
  const walk = (dir, depth) => {
    if (depth > MAX_DEPTH) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    const names = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));

    // npm: a package.json that isn't just a config shim (must declare deps or scripts)
    if (names.has('package.json')) {
      try {
        const pj = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
        if (pj.dependencies || pj.devDependencies || pj.scripts) pkgs.push({ dir, ecosystem: 'npm' });
      } catch { /* malformed package.json — skip */ }
    }
    if (names.has('go.mod')) pkgs.push({ dir, ecosystem: 'go' });
    if (names.has('requirements.txt') || names.has('pyproject.toml')) pkgs.push({ dir, ecosystem: 'python' });

    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) {
        walk(join(dir, e.name), depth + 1);
      }
    }
  };
  walk(root, 0);
  return pkgs;
}

// ── per-package dimension runners ────────────────────────────────────
// Returns {ok, tail}: on failure, `tail` is the last lines of the combined
// stderr+stdout so a held PR can say WHY it was held (ADR-007 observability).
const run = (cmd, cwd, timeoutMs = 600_000, extraEnv = {}) => {
  try {
    execSync(cmd, { cwd, stdio: 'pipe', timeout: timeoutMs, env: { ...process.env, CI: 'true', ...extraEnv } });
    return { ok: true, tail: '' };
  } catch (e) {
    const combined = `${e.stderr?.toString() || ''}${e.stdout?.toString() || ''}`;
    const lines = combined.split('\n').map((l) => l.replace(/\s+$/, '')).filter(Boolean);
    return { ok: false, tail: lines.slice(-14).join('\n') };
  }
};

function gatePackage(pkg) {
  const { dir, ecosystem } = pkg;
  let build = 'NOT_APPLICABLE', test = 'NOT_APPLICABLE', smoke = 'NOT_APPLICABLE';
  const errors = {}; // dimension -> failure tail, so a hold explains itself

  if (ecosystem === 'npm') {
    const pj = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    // BUILD: deps resolve (lockfile coherent) + compiles if a build script exists.
    // Fallback ladder: npm ci -> npm install -> npm install --legacy-peer-deps.
    // A peer-dependency conflict (ERESOLVE) is npm's resolver being strict, not
    // the security bump being unsafe — so we retry the way a human would rather
    // than failing BUILD and holding the fix forever (e.g. DriveIQ vite peer).
    const ci = run('npm ci', dir);
    let inst = ci.ok ? ci : run('npm install --no-audit --no-fund', dir);
    if (!inst.ok) inst = run('npm install --no-audit --no-fund --legacy-peer-deps', dir);
    if (!inst.ok) { build = 'FAIL'; errors.build = inst.tail; }
    else if (pj.scripts?.build) {
      const b = run('npm run build', dir);
      build = b.ok ? 'PASS' : 'FAIL';
      if (!b.ok) errors.build = b.tail;
    } else build = 'PASS';
    // TEST: only if a real test script exists
    const t = pj.scripts?.test || '';
    if (build !== 'FAIL' && t && !/no test specified/.test(t)) {
      const r = run('npm test', dir); test = r.ok ? 'PASS' : 'FAIL';
      if (!r.ok) errors.test = r.tail;
    }
    // SMOKE: declared entrypoint imports without immediate error. Pass the
    // entrypoint via env (not string-interpolated into the command) so a
    // hostile package.json `main` can't inject a shell/JS payload.
    if (build !== 'FAIL' && pj.main && existsSync(join(dir, pj.main))) {
      const r = run('node -e "require(process.env.GATE_SMOKE_MAIN)"', dir, 30_000, { GATE_SMOKE_MAIN: resolve(dir, pj.main) });
      smoke = r.ok ? 'PASS' : 'FAIL';
      if (!r.ok) errors.smoke = r.tail;
    }
  } else if (ecosystem === 'go') {
    const b = run('go build ./...', dir);
    build = b.ok ? 'PASS' : 'FAIL';
    if (!b.ok) errors.build = b.tail;
    if (build !== 'FAIL') {
      const hasTests = run('bash -c "find . -name \'*_test.go\' -not -path \'*/vendor/*\' | grep -q ."', dir, 15_000).ok;
      if (hasTests) { const r = run('go test ./...', dir); test = r.ok ? 'PASS' : 'FAIL'; if (!r.ok) errors.test = r.tail; }
    }
  } else if (ecosystem === 'python') {
    const b = existsSync(join(dir, 'requirements.txt'))
      ? run('pip install -r requirements.txt', dir)
      : run('pip install .', dir);
    build = b.ok ? 'PASS' : 'FAIL';
    if (!b.ok) errors.build = b.tail;
    if (build !== 'FAIL') {
      const hasPytest = run('python -c "import pytest"', dir, 15_000).ok &&
        (existsSync(join(dir, 'tests')) || run('bash -c "ls test_*.py >/dev/null 2>&1"', dir, 5_000).ok);
      if (hasPytest) { const r = run('pytest -q', dir); test = r.ok ? 'PASS' : 'FAIL'; if (!r.ok) errors.test = r.tail; }
    }
  }
  return { build, test, smoke, errors };
}

// ── human-readable hold reason (posted onto the held PR) ──────────────
function buildReport(verdict, perPackage) {
  if (verdict === 'GO') return '';
  const failing = perPackage.filter((p) => p.errors && Object.keys(p.errors).length > 0);
  const out = [`**Why this is held — gate verdict \`${verdict}\`:**`, ''];
  if (failing.length === 0) {
    out.push('No dimension produced executable evidence (green-by-absence): nothing built or tested, so the fix could not be verified. Add a build/test script so the gate can confirm the bump is safe.');
  } else {
    for (const p of failing) {
      for (const [dim, tail] of Object.entries(p.errors)) {
        out.push(
          `<details><summary><code>${p.package}</code> (${p.ecosystem}) — ${dim.toUpperCase()} FAILED</summary>`,
          '', '```', tail || '(no output captured)', '```', '</details>', '',
        );
      }
    }
  }
  return out.join('\n').slice(0, 60000); // GitHub comment body cap is 65536
}

// ── cross-package aggregation per dimension ──────────────────────────
function rollup(results, key) {
  if (results.some((r) => r[key] === 'FAIL')) return 'FAIL';
  if (results.some((r) => r[key] === 'PASS')) return 'PASS';
  return 'NOT_APPLICABLE';
}

// ── discover + gate a whole tree (optionally scoped to one package) ───
function gateTree(root, scope) {
  let pkgs = discover(root);
  if (scope) pkgs = pkgs.filter((p) => (relative(root, p.dir) || '.') === scope);
  return pkgs.map((p) => {
    const r = gatePackage(p);
    return { package: relative(root, p.dir) || '.', ecosystem: p.ecosystem, ...r };
  });
}

function buildDims(perPackage, from, to) {
  const dimKey = { BUILD: 'build', TEST: 'test', SMOKE: 'smoke' };
  const dims = ['BUILD', 'TEST', 'SMOKE'].map((d) => {
    const key = dimKey[d];
    const dim = { dimension: d, result: rollup(perPackage, key) };
    if (perPackage.some((p) => p[`${key}_preexisting`])) dim.preexisting = true;
    return dim;
  });
  dims.push({ dimension: 'SURFACE', result: surfaceForBump(from, to) });
  return dims;
}

// ── differential gate: neutralize failures that ALSO fail on the base ──
// A security fix is only blocked for a dimension it REGRESSES (passed on the
// base branch, fails on the fix branch). A dimension already red on base — a
// missing test file, a broken monorepo import, a build that never worked — is
// pre-existing repo debt, not the bump's fault, and must not hold the fix.
// This is the line between "the fix breaks the build" and "the build was
// already broken." Without it, any repo with a flaky/red main freezes forever.
function applyBaseline(fixPkgs, basePkgs) {
  const baseByPath = new Map(basePkgs.map((p) => [p.package, p]));
  const notes = [];
  for (const p of fixPkgs) {
    const base = baseByPath.get(p.package);
    for (const key of ['build', 'test', 'smoke']) {
      // Neutralize ONLY if the base has this package and did NOT pass the
      // dimension. If base passed it and the fix fails it, that's a genuine
      // regression and stays a FAIL (legitimately held for a human).
      if (p[key] === 'FAIL' && base && base[key] !== 'PASS') {
        p[`${key}_preexisting`] = true;
        if (p.errors && p.errors[key]) delete p.errors[key]; // no longer a hold reason
        p[key] = 'NOT_APPLICABLE'; // neutral for rollup + verdict
        notes.push(`\`${p.package}\` — ${key.toUpperCase()} fails on the base branch too; pre-existing, not counted as a regression.`);
      }
    }
  }
  return notes;
}

// ── SURFACE (mirrors surfaceForBump in src/core/verdict.ts) ───────────
function surfaceForBump(from, to) {
  const parse = (v) => {
    if (!v) return null;
    const m = v.replace(/^[^0-9]*/, '').match(/^(\d+)\.(\d+)\.(\d+)/);
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  };
  const a = parse(from), b = parse(to);
  if (!a || !b) return 'NOT_APPLICABLE';
  const breaking = a[0] !== b[0] || (a[0] === 0 && a[1] !== b[1]); // 0.x: minor is breaking
  return breaking ? 'FAIL' : 'PASS';
}

// ── verdict aggregation (mirrors aggregateVerdict in src/core/verdict.ts) ──
function aggregateVerdict(dims) {
  if (dims.some((d) => d.result === 'FAIL')) return 'NO-GO';
  if (dims.some((d) => d.result === 'PASS')) return 'GO';
  return 'GO-UNVERIFIED';
}

// ── main ─────────────────────────────────────────────────────────────
function main() {
  const args = process.argv.slice(2);
  // Resolve the target to an absolute, existing directory up front — the gate
  // only ever walks a checked-out repo, never an arbitrary caller-supplied path.
  const target = resolve(args[0] || '.');
  if (!existsSync(target) || !statSync(target).isDirectory()) {
    console.error(`run-gate: target is not a directory: ${target}`);
    process.exit(2);
  }
  const fromIdx = args.indexOf('--from');
  const toIdx = args.indexOf('--to');
  const from = fromIdx >= 0 ? args[fromIdx + 1] : '';
  const to = toIdx >= 0 ? args[toIdx + 1] : '';
  // --scope <dir>: gate ONLY the package at this manifest dir (ADR-007
  // per-package). Without it, an unrelated package's pre-existing build break
  // would hold a scoped fix that never touched it.
  const scopeIdx = args.indexOf('--scope');
  const scope = scopeIdx >= 0 ? (args[scopeIdx + 1] || '') : '';
  // --baseline <dir>: a checkout of the BASE branch, used to drop pre-existing
  // failures so repo debt can't hold a good security fix (differential gate).
  const baseIdx = args.indexOf('--baseline');
  const baseline = baseIdx >= 0 ? (args[baseIdx + 1] || '') : '';

  const perPackage = gateTree(target, scope);
  let dims = buildDims(perPackage, from, to);
  let verdict = aggregateVerdict(dims);
  let baselineNotes = [];

  // Only pay for the baseline gate when the fix isn't already clean. A GO needs
  // no baseline (nothing to excuse); a non-GO might be held purely by pre-existing
  // breakage, so re-judge it against the base branch before holding for a human.
  if (verdict !== 'GO' && baseline) {
    const baseDir = resolve(baseline);
    if (existsSync(baseDir) && statSync(baseDir).isDirectory()) {
      const basePkgs = gateTree(baseDir, scope);
      baselineNotes = applyBaseline(perPackage, basePkgs);
      if (baselineNotes.length) {
        dims = buildDims(perPackage, from, to);
        verdict = aggregateVerdict(dims);
      }
    }
  }

  let report = buildReport(verdict, perPackage);
  if (baselineNotes.length) {
    const head = verdict === 'GO'
      ? '**Differential gate — the security fix itself is clean; pre-existing failures were ignored:**'
      : '**Differential gate — these pre-existing failures were ignored (not regressions):**';
    report = [head, '', ...baselineNotes.map((n) => `- ${n}`), report ? '\n' + report : ''].join('\n').slice(0, 60000);
  }
  const out = {
    verdict, dimensions: dims, packages: perPackage,
    packagesDiscovered: perPackage.length, baselineApplied: baselineNotes.length > 0, report,
  };
  console.log(JSON.stringify(out, null, 2));

  if (process.env.GITHUB_OUTPUT) {
    const gho = process.env.GITHUB_OUTPUT;
    appendFileSync(gho, `verdict=${verdict}\n`);
    appendFileSync(gho, `dimensions=${JSON.stringify(dims)}\n`);
    appendFileSync(gho, `packages=${JSON.stringify(perPackage)}\n`);
    // multiline: heredoc-style delimiter (the build tail is multi-line)
    appendFileSync(gho, `report<<GATE_REPORT_EOF\n${report}\nGATE_REPORT_EOF\n`);
  }
  return out;
}

main();
