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
  .description('Run a security scan across all repositories via Advisory DB')
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

      spinner.text = 'Initializing fabric gateway...';
      await steer.initFabricGateway();

      const gateway = steer._getGateway();
      if (!gateway.available) {
        spinner.fail('Fabric gateway unavailable — cannot route scan');
        process.exit(1);
      }

      spinner.text = 'Scanning repositories via Advisory DB...';

      // Build scan args
      const scanArgs = {
        severity_threshold: options.severity.toUpperCase(),
        dry_run: !!options.dryRun,
      };

      // If --repo specified, pass it; otherwise gateway defaults to managed repos
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
        // Group findings by repo
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

      // Persist state
      if (!options.dryRun) {
        const state = steer._getState();
        state.addAuditEntry({
          action: 'cli_scan',
          result: 'success',
          details: {
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

        // Dashboard refresh
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

