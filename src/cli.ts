/**
 * SPAIDER Agent — CLI Entry Point
 * 
 * Parses command-line arguments and launches the pentest pipeline.
 * Supports --url, --repo, --output, --verbose, and --replay flags.
 */

import * as path from 'path';
import { PipelineConfig } from './types';
import { runPipeline } from './pipeline';
import { log, formatDuration } from './utils';

/**
 * Parse command-line arguments.
 * Supports: --url=<url> --repo=<path> --output=<path> --verbose --replay
 */
function parseArgs(args: string[]): Partial<{
  targetUrl: string;
  repoPath: string;
  outputDir: string;
  verbose: boolean;
  replay: boolean;
}> {
  const config: Record<string, string | boolean> = {};

  for (const arg of args) {
    if (arg.startsWith('--url=')) {
      config.targetUrl = arg.slice('--url='.length);
    } else if (arg.startsWith('--repo=')) {
      config.repoPath = arg.slice('--repo='.length);
    } else if (arg.startsWith('--output=')) {
      config.outputDir = arg.slice('--output='.length);
    } else if (arg === '--verbose') {
      config.verbose = true;
    } else if (arg === '--replay') {
      config.replay = true;
    } else if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    }
  }

  return config;
}

/**
 * Print CLI usage information.
 */
function printUsage(): void {
  console.log(`
SPAIDER Agent — AI-Powered Autonomous Vulnerability Scanner

Usage:
  npx ts-node src/cli.ts --url=<target> --repo=<path> [options]

Required Arguments:
  --url=<url>     Target URL (e.g., http://localhost:3000 or AWS instance URL)
  --repo=<path>   Path to target application source code

Options:
  --output=<path>  Output directory for deliverables (default: ./deliverables)
  --verbose        Enable detailed logging
  --replay         Use pre-computed deliverables instead of running agents
  --help, -h       Show this help message

Examples:
  # Test against local Juice Shop
  npx ts-node src/cli.ts --url=http://localhost:3000 --repo=./repos/juice-shop

  # Test against AWS-hosted instance
  npx ts-node src/cli.ts --url=http://ec2-xx-xx-xx-xx.compute.amazonaws.com:3000 --repo=./repos/juice-shop

  # Replay mode for demo
  npx ts-node src/cli.ts --url=http://localhost:3000 --repo=./repos/juice-shop --replay
`);
}

/**
 * Main entry point.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const parsed = parseArgs(args);

  // Validate required arguments
  if (!parsed.targetUrl) {
    console.error('Error: --url is required. Use --help for usage information.');
    process.exit(1);
  }
  if (!parsed.repoPath) {
    console.error('Error: --repo is required. Use --help for usage information.');
    process.exit(1);
  }

  const config: PipelineConfig = {
    targetUrl: parsed.targetUrl,
    repoPath: path.resolve(parsed.repoPath),
    outputDir: path.resolve(parsed.outputDir || './deliverables'),
    verbose: parsed.verbose || false,
    replay: parsed.replay || false,
  };

  log('SPAIDER Agent — Starting Pipeline');
  log(`  Target:  ${config.targetUrl}`);
  log(`  Repo:    ${config.repoPath}`);
  log(`  Output:  ${config.outputDir}`);
  log(`  Mode:    ${config.replay ? 'REPLAY' : 'LIVE'}`);
  log('');

  const startTime = Date.now();

  try {
    const result = await runPipeline(config);
    const duration = Date.now() - startTime;

    console.log('\n' + '═'.repeat(50));
    console.log('  SPAIDER Agent — Pipeline Summary');
    console.log('═'.repeat(50));
    console.log(`  Status:    ${result.success ? '✅ SUCCESS' : '❌ FAILED'}`);
    console.log(`  Duration:  ${formatDuration(duration)}`);
    console.log(`  Cost:      $${result.totalCost.toFixed(2)}`);
    console.log(`  Findings:  ${result.findingsCount}`);
    console.log(`  Phases:    ${result.phases.length} completed`);
    console.log('═'.repeat(50));

    process.exit(result.success ? 0 : 1);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log(`Fatal error: ${errorMessage}`, 'ERROR');
    process.exit(1);
  }
}

main();
