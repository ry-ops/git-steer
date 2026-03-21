#!/usr/bin/env node

/**
 * git-steer CLI
 * 
 * This is the ONLY code that lives locally (via npx).
 * Everything else is pulled from GitHub at runtime.
 */

import { Command } from 'commander';
import { GitSteer } from '../dist/index.js';
import { KeychainService } from '../dist/core/keychain.js';
import { SetupWizard } from '../dist/core/setup.js';
import chalk from 'chalk';
import ora from 'ora';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { version: VERSION } = require('../package.json');

const program = new Command();

program
  .name('git-steer')
  .description('Self-hosting GitHub autonomy engine')
  .version(VERSION);

program
  .command('init')
  .description('First-time setup: create GitHub App and state repo')
  .action(async () => {
    const wizard = new SetupWizard();
    await wizard.run();
  });

program
  .command('start', { isDefault: true })
  .description('Start git-steer MCP server')
  .option('--stdio', 'Use stdio transport (default)')
  .option('--http', 'Use HTTP/SSE transport')
  .option('--port <port>', 'HTTP port', '3333')
  .action(async (options) => {
    const spinner = ora('Starting git-steer...').start();
    
    try {
      const keychain = new KeychainService();
      
      // Check if initialized
      const appId = await keychain.get('git-steer-app-id');
      if (!appId) {
        spinner.fail('git-steer not initialized');
        console.log(chalk.yellow('\nRun `git-steer init` to set up.\n'));
        process.exit(1);
      }

      const steer = new GitSteer({ keychain });
      
      // Pull latest state from GitHub
      spinner.text = 'Syncing state from GitHub...';
      await steer.syncState();
      
      // Start MCP server
      spinner.text = 'Starting MCP server...';
      const transport = options.http ? 'http' : 'stdio';
      await steer.startServer({ 
        transport, 
        port: parseInt(options.port) 
      });
      
      spinner.succeed('git-steer running');
      
      if (transport === 'stdio') {
        // stdio mode - wait for input
      } else {
        console.log(chalk.green(`\nHTTP server listening on port ${options.port}`));
        console.log(chalk.dim('Press Ctrl+C to stop\n'));
      }
      
    } catch (error) {
      spinner.fail('Failed to start');
      console.error(chalk.red('Failed to start git-steer. Check your credentials and try again.'));
      if (process.env.DEBUG) console.error(String(error.message || 'Unknown error').replace(/ghp_\w+|gho_\w+|ghs_\w+|github_pat_\w+/g, '[REDACTED]'));
      process.exit(1);
    }
  });

program
  .command('web')
  .description('Start git-steer Fastify web server (REST API)')
  .option('--port <port>', 'Web server port', '4300')
  .action(async (options) => {
    const spinner = ora('Starting git-steer web server...').start();

    try {
      const keychain = new KeychainService();

      const appId = await keychain.get('git-steer-app-id');
      if (!appId) {
        spinner.fail('git-steer not initialized');
        console.log(chalk.yellow('\nRun `git-steer init` to set up.\n'));
        process.exit(1);
      }

      const steer = new GitSteer({ keychain });

      spinner.text = 'Syncing state from GitHub...';
      await steer.syncState();

      spinner.text = 'Starting web server...';
      await steer.startWeb({ port: parseInt(options.port) });

      spinner.succeed('git-steer web server running');
      console.log(chalk.green(`\nWeb server listening on port ${options.port}`));
      console.log(chalk.dim('Press Ctrl+C to stop\n'));
    } catch (error) {
      spinner.fail('Failed to start web server');
      console.error(chalk.red('Failed to start git-steer web server.'));
      if (process.env.DEBUG) console.error(String(error.message || 'Unknown error').replace(/ghp_\w+|gho_\w+|ghs_\w+|github_pat_\w+/g, '[REDACTED]'));
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show git-steer status and health')
  .action(async () => {
    try {
      const keychain = new KeychainService();
      const steer = new GitSteer({ keychain });
      await steer.showStatus();
    } catch (error) {
      console.error(chalk.red('Failed to retrieve status. Check your credentials and try again.'));
      if (process.env.DEBUG) console.error(String(error.message || 'Unknown error').replace(/ghp_\w+|gho_\w+|ghs_\w+|github_pat_\w+/g, '[REDACTED]'));
      process.exit(1);
    }
  });

program
  .command('sync')
  .description('Force sync state to GitHub')
  .action(async () => {
    const spinner = ora('Syncing state to GitHub...').start();
    try {
      const keychain = new KeychainService();
      const steer = new GitSteer({ keychain });
      await steer.syncState();
      await steer.forceSyncState();
      spinner.succeed('State synced');
    } catch (error) {
      spinner.fail('Sync failed');
      console.error(chalk.red('Failed to sync state. Check your credentials and try again.'));
      if (process.env.DEBUG) console.error(String(error.message || 'Unknown error').replace(/ghp_\w+|gho_\w+|ghs_\w+|github_pat_\w+/g, '[REDACTED]'));
      process.exit(1);
    }
  });

program
  .command('scan')
  .alias('security-scan')
  .description('Run a security scan across all repositories')
  .option('--repo <repo>', 'Scan a specific repo (owner/name) instead of all')
  .option('--severity <level>', 'Minimum severity: CRITICAL, HIGH, MEDIUM, LOW', 'HIGH')
  .option('--dry-run', 'Scan without persisting to queue')
  .option('--no-dashboard', 'Skip dashboard refresh after scan')
  .action(async (options) => {
    const spinner = ora('Initializing security scan...').start();
    try {
      const keychain = new KeychainService();

      const appId = await keychain.get('git-steer-app-id');
      if (!appId) {
        spinner.fail('git-steer not initialized');
        console.log(chalk.yellow('\nRun `git-steer init` to set up.\n'));
        process.exit(1);
      }

      const steer = new GitSteer({ keychain });
      await steer.syncState();

      // --- Try gateway path, fall back to Dependabot REST ---
      let useGateway = false;
      spinner.text = 'Initializing fabric gateway...';
      try {
        await steer.initFabricGateway();
        const gateway = steer._getGateway();
        useGateway = gateway.available;
      } catch {
        // Gateway init failed — fall back silently
      }

      if (useGateway) {
        // ========== Gateway path (Advisory DB + queue + dashboard) ==========
        const gateway = steer._getGateway();
        spinner.text = 'Scanning repositories via Advisory DB...';

        const scanArgs = {
          severity_threshold: options.severity.toUpperCase(),
          dry_run: !!options.dryRun,
        };
        if (options.repo) {
          scanArgs.repos = [options.repo];
        }

        const routeResult = await gateway.router.route('cve_scan', scanArgs);
        const scanResult = typeof routeResult.result === 'string'
          ? JSON.parse(routeResult.result)
          : routeResult.result;

        const reposScanned = scanResult.reposScanned || 0;
        const findings = scanResult.findings || [];
        const bySeverity = scanResult.bySeverity || {};
        const queued = scanResult.queued || 0;
        const duplicates = scanResult.duplicates || 0;
        const totalFindings = findings.length;

        spinner.succeed(`Scan complete: ${reposScanned} repos scanned via Advisory DB`);
        console.log('');

        if (totalFindings === 0) {
          console.log(chalk.green('  No vulnerabilities found!'));
        } else {
          const byRepo = {};
          for (const f of findings) {
            const repo = f.repo || 'unknown';
            if (!byRepo[repo]) byRepo[repo] = [];
            byRepo[repo].push(f);
          }
          const repoCount = Object.keys(byRepo).length;

          console.log(`  ${chalk.red(String(totalFindings))} vulnerabilities across ${repoCount} repos:\n`);

          if (bySeverity.CRITICAL) console.log(chalk.red(`  CRITICAL: ${bySeverity.CRITICAL}`));
          if (bySeverity.HIGH) console.log(chalk.hex('#db6d28')(`  HIGH:     ${bySeverity.HIGH}`));
          if (bySeverity.MEDIUM) console.log(chalk.yellow(`  MEDIUM:   ${bySeverity.MEDIUM}`));
          if (bySeverity.LOW) console.log(chalk.green(`  LOW:      ${bySeverity.LOW}`));

          console.log('');
          for (const [repo, alerts] of Object.entries(byRepo)) {
            console.log(chalk.blue(`  ${repo}`) + chalk.dim(` (${alerts.length} alerts)`));
            for (const a of alerts) {
              const sev = (a.severity || 'unknown').toUpperCase();
              const sevColor = sev === 'CRITICAL' ? chalk.red : sev === 'HIGH' ? chalk.hex('#db6d28') : sev === 'MEDIUM' ? chalk.yellow : chalk.green;
              const pkg = a.affectedPackage || a.id || 'unknown';
              const fix = a.patchedVersion ? chalk.dim(` → fix: ${a.patchedVersion}`) : '';
              console.log(`    ${sevColor(sev.padEnd(9))} ${pkg}${fix}`);
            }
          }

          if (!options.dryRun) {
            console.log('');
            console.log(chalk.dim(`  ${queued} findings queued to cve-queue.jsonl`));
            if (duplicates > 0) {
              console.log(chalk.dim(`  ${duplicates} duplicates skipped`));
            }
          }
        }

        // Persist state + dashboard
        if (!options.dryRun) {
          const state = steer._getState();
          state.addAuditEntry({
            action: 'cli_scan',
            result: 'success',
            details: {
              source: 'gateway',
              reposScanned,
              findings: totalFindings,
              queued,
              duplicates,
              severity: options.severity.toUpperCase(),
            },
          });
          spinner.start('Saving state...');
          await steer.forceSyncState();
          spinner.succeed('State saved');

          if (options.dashboard !== false) {
            spinner.start('Updating dashboard...');
            try {
              const dash = await steer.refreshDashboard();
              spinner.succeed(`Dashboard updated: ${dash.dashboardUrl}`);
            } catch (err) {
              spinner.warn(`Dashboard update failed: ${err.message}`);
            }
          }
        }
      } else {
        // ========== Fallback path (Dependabot REST — no queue/dashboard) ==========
        if (!options.dryRun) {
          spinner.warn('Fabric gateway unavailable — falling back to Dependabot REST (no queue persistence)');
        } else {
          spinner.info('Fabric gateway unavailable — using Dependabot REST');
        }

        spinner.start('Scanning repositories via Dependabot REST...');

        const github = steer._getGitHub();
        const repos = options.repo
          ? [{ owner: options.repo.split('/')[0], name: options.repo.split('/')[1], fullName: options.repo }]
          : await github.listRepos();

        const severityOrder = ['critical', 'high', 'medium', 'low'];
        const minSeverityIndex = options.severity.toLowerCase() === 'all'
          ? 4
          : severityOrder.indexOf(options.severity.toLowerCase());
        const results = {};

        for (const repo of repos) {
          try {
            const alerts = await github.getSecurityAlertsDetailed(
              repo.owner || options.repo?.split('/')[0],
              repo.name
            );
            const filtered = alerts.filter((a) => {
              const idx = severityOrder.indexOf(a.severity);
              return idx >= 0 && idx <= minSeverityIndex;
            });
            if (filtered.length > 0) {
              results[repo.fullName || `${repo.owner}/${repo.name}`] = filtered;
            }
          } catch {
            // Skip repos we can't access
          }
        }

        const totalAlerts = Object.values(results).flat().length;
        const reposWithAlerts = Object.keys(results).length;

        spinner.succeed(`Scan complete: ${repos.length} repos scanned via Dependabot REST`);
        console.log('');

        if (totalAlerts === 0) {
          console.log(chalk.green('  No vulnerabilities found!'));
        } else {
          console.log(chalk.red(`  ${totalAlerts} vulnerabilities across ${reposWithAlerts} repos:\n`));

          const flat = Object.values(results).flat();
          const bySev = {
            critical: flat.filter(a => a.severity === 'critical').length,
            high: flat.filter(a => a.severity === 'high').length,
            medium: flat.filter(a => a.severity === 'medium').length,
            low: flat.filter(a => a.severity === 'low').length,
          };

          if (bySev.critical) console.log(chalk.red(`  CRITICAL: ${bySev.critical}`));
          if (bySev.high) console.log(chalk.hex('#db6d28')(`  HIGH:     ${bySev.high}`));
          if (bySev.medium) console.log(chalk.yellow(`  MEDIUM:   ${bySev.medium}`));
          if (bySev.low) console.log(chalk.green(`  LOW:      ${bySev.low}`));

          console.log('');
          for (const [repo, alerts] of Object.entries(results)) {
            console.log(chalk.blue(`  ${repo}`) + chalk.dim(` (${alerts.length} alerts)`));
            for (const a of alerts) {
              const sevColor = a.severity === 'critical' ? chalk.red : a.severity === 'high' ? chalk.hex('#db6d28') : a.severity === 'medium' ? chalk.yellow : chalk.green;
              console.log(`    ${sevColor(a.severity.toUpperCase().padEnd(9))} ${a.package || a.cve || 'unknown'}${a.fixVersion ? chalk.dim(` → fix: ${a.fixVersion}`) : ''}`);
            }
          }
        }

        console.log('');
        console.log(chalk.dim('  Tip: Install @git-fabric/gateway and @git-fabric/cve for queue persistence + dashboard refresh.'));
      }

      console.log('');
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red('Failed to run security scan.'));
      if (process.env.DEBUG) console.error(String(error.message || 'Unknown error').replace(/ghp_\w+|gho_\w+|ghs_\w+|github_pat_\w+/g, '[REDACTED]'));
      process.exit(1);
    }
  });

program
  .command('reset')
  .description('Remove all local credentials (does not affect GitHub)')
  .action(async () => {
    const keychain = new KeychainService();
    await keychain.clear();
    console.log(chalk.green('Credentials removed from Keychain'));
  });

program.parse();

