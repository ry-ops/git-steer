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

const VERSION = '0.1.0';

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
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show git-steer status and health')
  .action(async () => {
    const keychain = new KeychainService();
    const steer = new GitSteer({ keychain });
    await steer.showStatus();
  });

program
  .command('sync')
  .description('Force sync state to GitHub')
  .action(async () => {
    const spinner = ora('Syncing state to GitHub...').start();
    const keychain = new KeychainService();
    const steer = new GitSteer({ keychain });
    await steer.forceSyncState();
    spinner.succeed('State synced');
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

