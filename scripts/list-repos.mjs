import keytar from 'keytar';
import { App } from 'octokit';

const SERVICE = 'git-steer';

const appId = await keytar.getPassword(SERVICE, 'git-steer-app-id');
const privateKey = await keytar.getPassword(SERVICE, 'git-steer-private-key');
const installationId = await keytar.getPassword(SERVICE, 'git-steer-installation-id');

const app = new App({ appId, privateKey });
const octokit = await app.getInstallationOctokit(Number(installationId));

// List all repos
const { data } = await octokit.request('GET /installation/repositories');

console.log('\n=== YOUR REPOS ===\n');
console.log('Total:', data.repositories.length, 'repositories\n');

const repos = data.repositories
  .filter(r => !r.archived)
  .sort((a, b) => new Date(b.pushed_at) - new Date(a.pushed_at));

for (const repo of repos) {
  const visibility = repo.private ? 'private' : 'public';
  const pushed = new Date(repo.pushed_at).toLocaleDateString();
  console.log(`[${visibility}] ${repo.name} (pushed: ${pushed})`);
}

// Check security alerts
console.log('\n=== SECURITY ALERTS ===\n');

let totalAlerts = 0;
for (const repo of repos.slice(0, 10)) {
  try {
    const { data: alerts } = await octokit.request(
      'GET /repos/{owner}/{repo}/dependabot/alerts',
      { owner: repo.owner.login, repo: repo.name, state: 'open' }
    );
    if (alerts.length > 0) {
      console.log(`${repo.name}: ${alerts.length} alert(s)`);
      for (const alert of alerts.slice(0, 3)) {
        const sev = alert.security_advisory?.severity || 'unknown';
        const pkg = alert.dependency?.package?.name || 'unknown';
        console.log(`  - [${sev}] ${pkg}`);
      }
      if (alerts.length > 3) {
        console.log(`  ... and ${alerts.length - 3} more`);
      }
      totalAlerts += alerts.length;
    }
  } catch (e) {
    // Skip repos where we can't access alerts
  }
}

if (totalAlerts === 0) {
  console.log('No open security alerts found in your top 10 repos!');
} else {
  console.log(`\nTotal: ${totalAlerts} open alerts`);
}
