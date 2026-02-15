#!/usr/bin/env node

const { Command } = require('commander');
const Monitor = require('./monitor');
const { loadConfig, validateDomains } = require('./config');

const program = new Command();

program
  .name('github-leak-scanner')
  .description('Monitor GitHub repositories, gists, and commits for leaked credentials')
  .version('1.0.0')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-d, --domains <domains>', 'Comma-separated list of domains to monitor')
  .option('-o, --once', 'Run once and exit (default is continuous monitoring)')
  .option('-i, --interval <minutes>', 'Check interval in minutes', '30')
  .option('-t, --token <token>', 'GitHub personal access token')
  .option('-v, --verbose', 'Verbose output')
  .parse(process.argv);

const options = program.opts();

async function main() {
  console.log('🔍 GitHub Leak Scanner');
  console.log('==========================\n');

  // Load configuration
  const config = loadConfig(options.config);
  
  // Get domains from CLI or config
  let domains = [];
  if (options.domains) {
    domains = options.domains.split(',').map(d => d.trim());
  } else if (config.domains) {
    domains = config.domains;
  } else {
    console.error('Error: No domains specified. Use -d option or config.json');
    process.exit(1);
  }

  // Validate domains
  const validDomains = validateDomains(domains);
  if (validDomains.length === 0) {
    console.error('Error: No valid domains provided');
    process.exit(1);
  }

  // Get GitHub token
  const token = options.token || config.githubToken || process.env.GITHUB_TOKEN;
  if (!token) {
    console.warn('Warning: No GitHub token provided. Rate limits will be lower.');
  }

  console.log(`Monitoring ${validDomains.length} domain(s): ${validDomains.join(', ')}`);
  console.log(`Check interval: ${options.interval} minutes`);
  console.log(`Mode: ${options.once ? 'Single scan' : 'Continuous monitoring'}\n`);

  const monitor = new Monitor(validDomains, {
    interval: parseInt(options.interval) * 60 * 1000,
    verbose: options.verbose,
    once: options.once,
    token: token
  });

  try {
    await monitor.start();
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
