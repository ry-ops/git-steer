/**
 * First-time setup wizard
 * 
 * Guides user through:
 * 1. Creating a GitHub App
 * 2. Installing it to their account
 * 3. Creating the state repo
 * 4. Storing credentials in Keychain
 */

import { KeychainService } from './keychain.js';
import { Octokit } from 'octokit';
import chalk from 'chalk';
import ora from 'ora';
import { createServer } from 'http';
import { URL } from 'url';
import open from 'open';

const STATE_REPO_NAME = 'git-steer-state';

// GitHub App manifest for creation
const APP_MANIFEST = {
  name: 'git-steer',
  url: 'https://github.com/ry-ops/git-steer',
  hook_attributes: {
    url: 'https://example.com/webhook', // Placeholder, we use polling
    active: false,
  },
  redirect_url: 'http://localhost:9876/callback',
  callback_urls: ['http://localhost:9876/callback'],
  public: false,
  default_permissions: {
    // Repository permissions
    actions: 'write',
    administration: 'write',
    contents: 'write',
    issues: 'write',
    metadata: 'read',
    pull_requests: 'write',
    security_events: 'read',
    secrets: 'write',
    workflows: 'write',
    // Organization permissions
    members: 'read',
    organization_administration: 'read',
    organization_hooks: 'read',
  },
  default_events: [],
};

export class SetupWizard {
  private keychain: KeychainService;

  constructor() {
    this.keychain = new KeychainService();
  }

  async run(): Promise<void> {
    console.log(chalk.bold('\n🚜 git-steer setup\n'));
    console.log('This will:');
    console.log('  1. Create a GitHub App for git-steer');
    console.log('  2. Install it to your account');
    console.log(`  3. Create a private repo: ${STATE_REPO_NAME}`);
    console.log('  4. Store credentials in macOS Keychain\n');

    // Check if already initialized
    const existing = await this.keychain.get('git-steer-app-id');
    if (existing) {
      console.log(chalk.yellow('git-steer is already initialized.'));
      console.log('Run `git-steer reset` first to reconfigure.\n');
      return;
    }

    // Step 1: Create GitHub App via manifest flow
    const appCredentials = await this.createGitHubApp();
    
    // Step 2: Install the app
    const installationId = await this.installApp(appCredentials.appId);
    
    // Step 3: Create state repo (pass installationId directly since it's not in keychain yet)
    await this.createStateRepo(appCredentials, installationId);

    // Step 4: Store in Keychain
    await this.storeCredentials({
      ...appCredentials,
      installationId,
    });

    console.log(chalk.green('\n✅ git-steer is ready!\n'));
    console.log('Run `git-steer` to start the MCP server.\n');
  }

  private async createGitHubApp(): Promise<{
    appId: string;
    privateKey: string;
    clientId: string;
    clientSecret: string;
  }> {
    const spinner = ora('Creating GitHub App...').start();

    return new Promise((resolve, reject) => {
      let resolved = false;

      // Start local server to receive callback
      const server = createServer(async (req, res) => {
        const url = new URL(req.url || '/', `http://localhost:9876`);

        if (url.pathname === '/callback') {
          const code = url.searchParams.get('code');

          if (code) {
            try {
              // Exchange code for app credentials
              const octokit = new Octokit();
              const response = await octokit.request(
                'POST /app-manifests/{code}/conversions',
                { code }
              );

              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end(`
                <html>
                  <body style="font-family: system-ui; padding: 40px; text-align: center;">
                    <h1>GitHub App created!</h1>
                    <p>You can close this window and return to the terminal.</p>
                  </body>
                </html>
              `);

              resolved = true;
              server.close();
              spinner.succeed('GitHub App created');

              resolve({
                appId: String(response.data.id),
                privateKey: response.data.pem,
                clientId: response.data.client_id,
                clientSecret: response.data.client_secret,
              });
            } catch (error) {
              res.writeHead(500, { 'Content-Type': 'text/plain' });
              res.end('Failed to create GitHub App');
              server.close();
              spinner.fail('Failed to create GitHub App');
              reject(error);
            }
          } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Missing code parameter');
          }
        } else {
          // Handle non-callback paths
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not found');
        }
      });

      server.listen(9876, async () => {
        // Open browser for app creation
        const manifestUrl = new URL('https://github.com/settings/apps/new');
        manifestUrl.searchParams.set('manifest', JSON.stringify(APP_MANIFEST));
        
        spinner.text = 'Opening browser for GitHub App creation...';
        await open(manifestUrl.toString());
        spinner.text = 'Waiting for GitHub App creation...';
      });

      // Timeout after 5 minutes
      setTimeout(() => {
        if (!resolved) {
          server.close();
          spinner.fail('Timed out waiting for GitHub App creation');
          reject(new Error('Timeout'));
        }
      }, 5 * 60 * 1000);
    });
  }

  private async installApp(_appId: string): Promise<string> {
    const spinner = ora('Waiting for app installation...').start();

    // Open installation page
    const installUrl = `https://github.com/apps/git-steer/installations/new`;
    await open(installUrl);

    spinner.text = 'Install the app in the browser, then press Enter...';
    
    // Wait for user to press Enter
    await new Promise<void>((resolve) => {
      process.stdin.once('data', () => resolve());
    });

    // Prompt for installation ID
    spinner.stop();
    console.log(chalk.yellow('\nEnter your installation ID (from the URL after installing):'));
    console.log(chalk.dim('(URL looks like: github.com/settings/installations/12345678)\n'));

    const installationId = await new Promise<string>((resolve) => {
      process.stdin.once('data', (data) => {
        resolve(data.toString().trim());
      });
    });

    // Validate the installation ID
    const parsed = parseInt(installationId, 10);
    if (isNaN(parsed) || parsed <= 0) {
      throw new Error(`Invalid installation ID: "${installationId}". Must be a positive number.`);
    }

    spinner.succeed('App installed');
    return installationId;
  }

  private async createStateRepo(
    appCredentials: { appId: string; privateKey: string },
    installationId: string
  ): Promise<void> {
    const spinner = ora(`Creating ${STATE_REPO_NAME} repo...`).start();

    try {
      const { App } = await import('octokit');
      const app = new App({
        appId: appCredentials.appId,
        privateKey: appCredentials.privateKey,
      });

      // Get installation token using passed installationId (not yet in keychain)
      const octokit = await app.getInstallationOctokit(Number(installationId));

      // Get authenticated user
      const { data: user } = await octokit.request('GET /user');

      // Create private repo
      await octokit.request('POST /user/repos', {
        name: STATE_REPO_NAME,
        description: 'State repository for git-steer. Do not edit manually.',
        private: true,
        auto_init: true,
      });

      // Create initial structure
      const files = [
        {
          path: 'config/managed-repos.yaml',
          content: `# Repositories managed by git-steer
repos: []
`,
        },
        {
          path: 'config/policies.yaml',
          content: `# Branch protection and automation policies
policies:
  default-branch-protection:
    branches: [main, master]
    protection:
      required_reviews: 1
      dismiss_stale_reviews: true
`,
        },
        {
          path: 'config/schedules.yaml',
          content: `# Scheduled jobs
schedules: {}
`,
        },
        {
          path: 'state/audit.jsonl',
          content: '',
        },
        {
          path: 'state/jobs.jsonl',
          content: '',
        },
        {
          path: 'state/cache.json',
          content: '{}',
        },
      ];

      for (const file of files) {
        await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
          owner: user.login,
          repo: STATE_REPO_NAME,
          path: file.path,
          message: `Initialize ${file.path}`,
          content: Buffer.from(file.content).toString('base64'),
        });
      }

      spinner.succeed(`Created ${user.login}/${STATE_REPO_NAME}`);
    } catch (error: any) {
      if (error.status === 422) {
        spinner.warn(`${STATE_REPO_NAME} already exists`);
      } else {
        spinner.fail('Failed to create state repo');
        throw error;
      }
    }
  }

  private async storeCredentials(credentials: {
    appId: string;
    privateKey: string;
    installationId: string;
  }): Promise<void> {
    const spinner = ora('Storing credentials in Keychain...').start();

    await this.keychain.set('git-steer-app-id', credentials.appId);
    await this.keychain.set('git-steer-private-key', credentials.privateKey);
    await this.keychain.set('git-steer-installation-id', credentials.installationId);
    await this.keychain.set('git-steer-state-repo', STATE_REPO_NAME);

    spinner.succeed('Credentials stored in Keychain');
  }
}
