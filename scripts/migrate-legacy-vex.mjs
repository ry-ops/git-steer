/**
 * migrate-legacy-vex.mjs — normalize pre-ledger _vex entries to the canonical
 * OpenVEX shape (ADR-004 C-004-003) and log each migration to the vex.jsonl
 * ledger.
 *
 * Legacy entries (written by the old vex-no-fix.mjs) used {cveId, setAt, setBy}
 * and status "affected" with null justification/action_statement — which now
 * fails validation. They were auto no-fix markers, so the honest compliant
 * status is "under_investigation".
 *
 * Build first: `npm run build`.
 */

import keytar from 'keytar';
import { App } from 'octokit';
import { validateVexInput, makeVexLedgerEntry } from '../dist/core/vex.js';
import { appendJsonl } from './lib/state-jsonl.mjs';

const PURL_TYPE = { npm: 'npm', pip: 'pypi', pypi: 'pypi', go: 'golang', gomod: 'golang', maven: 'maven', nuget: 'nuget', rubygems: 'gem', composer: 'composer', cargo: 'cargo' };

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');
const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));
const owner = (await octokit.request('GET /installation/repositories', { per_page: 1 })).data.repositories[0].owner.login;

const STATE_REPO = 'git-steer-state';
const { data: file } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', { owner, repo: STATE_REPO, path: 'state/cache.json' });
const cacheJson = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));
const vex = cacheJson._vex || {};

const isLegacy = (e) => !e.cve_id || e.cveId || e.setAt;
const now = new Date().toISOString();
const ledgerRows = [];
let migrated = 0;

for (const [key, old] of Object.entries(vex)) {
  if (!isLegacy(old)) continue;

  const repo = old.repo && old.owner ? `${old.owner}/${old.repo}` : key.split('::')[0];
  const cveId = old.cve_id || old.cveId || key.split('::')[1];
  // Best-effort PURL from the legacy detail string ("Package: nltk, severity: ...")
  const pkgMatch = (old.detail || '').match(/Package:\s*([^,\s]+)/i);
  const purl = pkgMatch ? `pkg:${PURL_TYPE['pip']}/${pkgMatch[1].toLowerCase()}` : undefined;

  // affected-with-no-action no-fix marker -> compliant under_investigation
  const newStatus = old.status === 'affected' && !old.action_statement ? 'under_investigation' : old.status;

  const entry = {
    cve_id: cveId,
    repo,
    product_purl: purl,
    status: newStatus,
    detail: (old.detail || '') + ' [migrated from legacy affected/no-justification]',
    created_at: old.setAt || old.created_at || now,
    updated_by: old.setBy || old.updated_by || 'cli:migrate-legacy-vex',
  };

  const err = validateVexInput(entry);
  if (err) { console.error(`  [skip] ${key}: ${err}`); continue; }

  vex[key] = entry;
  ledgerRows.push(makeVexLedgerEntry(entry, old.status ?? null, 'cli:migrate-legacy-vex', now));
  migrated++;
  console.log(`  ✓ ${repo}  ${cveId}: ${old.status} → ${newStatus}${purl ? '  ' + purl : ''}`);
}

if (migrated === 0) {
  console.log('No legacy entries to migrate.');
  process.exit(0);
}

cacheJson._vex = vex;
await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
  owner, repo: STATE_REPO, path: 'state/cache.json',
  message: `vex: migrate ${migrated} legacy entries to canonical OpenVEX shape`,
  content: Buffer.from(JSON.stringify(cacheJson, null, 2)).toString('base64'),
  sha: file.sha,
});
await appendJsonl(octokit, owner, STATE_REPO, 'state/vex.jsonl', ledgerRows);

console.log(`\nMigrated ${migrated} legacy entries (+${ledgerRows.length} ledger rows).`);
