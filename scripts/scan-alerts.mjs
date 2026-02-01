import keytar from 'keytar';
import { App } from 'octokit';

const appId = await keytar.getPassword('git-steer', 'git-steer-app-id');
const privateKey = await keytar.getPassword('git-steer', 'git-steer-private-key');
const installationId = await keytar.getPassword('git-steer', 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

const { data } = await octokit.request('GET /installation/repositories');
const repos = data.repositories.filter(r => !r.archived);

console.log('Scanning', repos.length, 'repos for security alerts...\n');

let totalAlerts = 0;
const reposWithAlerts = [];

for (const repo of repos) {
  try {
    const { data: alerts } = await octokit.request(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      { owner: repo.owner.login, repo: repo.name, state: 'open' }
    );
    if (alerts.length > 0) {
      reposWithAlerts.push({ name: repo.name, alerts });
      totalAlerts += alerts.length;
      process.stdout.write('!');
    } else {
      process.stdout.write('.');
    }
  } catch (e) {
    process.stdout.write('x');
  }
}

console.log('\n');

if (reposWithAlerts.length === 0) {
  console.log('No open security alerts found across all repos!');
} else {
  console.log('=== SECURITY ALERTS ===\n');
  for (const { name, alerts } of reposWithAlerts) {
    console.log(`${name}: ${alerts.length} alert(s)`);
    const bySeverity = { critical: [], high: [], medium: [], low: [] };
    for (const a of alerts) {
      const sev = a.security_advisory?.severity || 'low';
      const pkg = a.dependency?.package?.name || 'unknown';
      if (bySeverity[sev]) bySeverity[sev].push(pkg);
    }
    for (const [sev, pkgs] of Object.entries(bySeverity)) {
      if (pkgs.length > 0) {
        console.log(`  [${sev.toUpperCase()}] ${pkgs.join(', ')}`);
      }
    }
    console.log('');
  }
  console.log(`Total: ${totalAlerts} open alerts across ${reposWithAlerts.length} repos`);
}
