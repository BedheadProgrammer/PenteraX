#!/usr/bin/env npx ts-node
/**
 * PenteraX — TypeScript CLI Entrypoint
 *
 * Usage:
 *   npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop
 *   npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop --verbose
 *   npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop --replay
 *
 * Phase 3 — Stream A2
 */

import * as path from "node:path";
import * as fs from "node:fs";
import { runPipeline, verifyDeliverables, type PipelineResultTS } from "./pipeline";

// ── Argument parsing ────────────────────────────────────────────────────────

interface CliArgs {
  url: string;
  repo: string;
  verbose: boolean;
  apiKey?: string;
  output?: string;
  retries?: number;
  budget?: number;
  replay: boolean;
  resumeFrom?: "recon" | "analysis" | "exploit" | "report";
}

function printUsage(): void {
  console.log(`
PenteraX — Agentic Cybersecurity Pipeline (TypeScript CLI)

Usage:
  npx ts-node src/cli.ts --url=<target> --repo=<path> [options]

Required:
  --url=<url>           Target URL to pentest
  --repo=<path>         Path to the target repository source code

Options:
  --verbose             Enable debug logging
  --api-key=<key>       Anthropic API key (default: $ANTHROPIC_API_KEY)
  --output=<dir>        Output directory (default: ./deliverables)
  --retries=<n>         Max retries per phase (default: 3)
  --budget=<usd>        Max API budget in USD (default: 10.0)
  --replay              Use pre-recorded deliverables (no API calls)
  --resume-from=<phase> Resume from phase: recon|analysis|exploit|report
  --help                Show this help message

Examples:
  npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop
  npx ts-node src/cli.ts --url=http://localhost:3000 --repo=./repos/juice-shop --verbose --replay
`.trim());
}

function parseArgs(argv: string[]): CliArgs | null {
  const args: Partial<CliArgs> = {
    verbose: false,
    replay: false,
  };

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    }

    if (arg === "--verbose" || arg === "-v") {
      args.verbose = true;
      continue;
    }

    if (arg === "--replay") {
      args.replay = true;
      continue;
    }

    // Handle --key=value style arguments
    const match = arg.match(/^--([a-z-]+)=(.+)$/);
    if (match) {
      const [, key, value] = match;
      switch (key) {
        case "url":
          args.url = value;
          break;
        case "repo":
          args.repo = value;
          break;
        case "api-key":
          args.apiKey = value;
          break;
        case "output":
          args.output = value;
          break;
        case "retries":
          args.retries = parseInt(value, 10);
          break;
        case "budget":
          args.budget = parseFloat(value);
          break;
        case "resume-from":
          if (["recon", "analysis", "exploit", "report"].includes(value)) {
            args.resumeFrom = value as CliArgs["resumeFrom"];
          } else {
            console.error(`Error: Invalid --resume-from value: ${value}`);
            console.error("  Valid values: recon, analysis, exploit, report");
            return null;
          }
          break;
        default:
          console.error(`Error: Unknown argument --${key}`);
          return null;
      }
      continue;
    }

    // Handle --key value style arguments (two-part)
    // Handled in a second pass below
  }

  // Second pass: Handle --key value (space-separated) style
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg.includes("=")) continue; // Already processed

    switch (arg) {
      case "--url":
        if (next && !next.startsWith("--")) { args.url = next; i++; }
        break;
      case "--repo":
        if (next && !next.startsWith("--")) { args.repo = next; i++; }
        break;
      case "--api-key":
        if (next && !next.startsWith("--")) { args.apiKey = next; i++; }
        break;
      case "--output":
        if (next && !next.startsWith("--")) { args.output = next; i++; }
        break;
      case "--retries":
        if (next && !next.startsWith("--")) { args.retries = parseInt(next, 10); i++; }
        break;
      case "--budget":
        if (next && !next.startsWith("--")) { args.budget = parseFloat(next); i++; }
        break;
      case "--resume-from":
        if (next && !next.startsWith("--")) {
          if (["recon", "analysis", "exploit", "report"].includes(next)) {
            args.resumeFrom = next as CliArgs["resumeFrom"];
          } else {
            console.error(`Error: Invalid --resume-from value: ${next}`);
            return null;
          }
          i++;
        }
        break;
    }
  }

  // Validate required arguments
  if (!args.url) {
    console.error("Error: --url is required.");
    console.error('  Example: --url=http://54.146.141.88:3000');
    return null;
  }

  if (!args.repo) {
    console.error("Error: --repo is required.");
    console.error("  Example: --repo=./repos/juice-shop");
    return null;
  }

  // Validate URL format
  try {
    new URL(args.url);
  } catch {
    console.error(`Error: Invalid URL: ${args.url}`);
    return null;
  }

  // Validate repo path exists
  const repoResolved = path.resolve(args.repo);
  if (!fs.existsSync(repoResolved)) {
    console.error(`Error: Repo path not found: ${repoResolved}`);
    return null;
  }

  return args as CliArgs;
}

// ── Formatting helpers ──────────────────────────────────────────────────────

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const min = Math.floor(seconds / 60);
  const sec = seconds % 60;
  return `${min}m ${sec.toFixed(0)}s`;
}

function printBanner(args: CliArgs): void {
  console.log("");
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║         PenteraX — Agentic Pentest Pipeline     ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log("");
  console.log(`  Target:  ${args.url}`);
  console.log(`  Repo:    ${path.resolve(args.repo)}`);
  console.log(`  Output:  ${args.output ?? "./deliverables"}`);
  console.log(`  Verbose: ${args.verbose}`);
  if (args.replay) console.log("  Mode:    REPLAY (no API calls)");
  if (args.resumeFrom) console.log(`  Resume:  from '${args.resumeFrom}'`);
  console.log("");
}

function printResult(result: PipelineResultTS): void {
  console.log("");
  console.log("═".repeat(60));
  console.log(`Pipeline complete in ${formatDuration(result.totalDurationSeconds)}`);
  console.log(`Deliverables generated: ${result.deliverablesGenerated.length}`);
  for (const d of result.deliverablesGenerated) {
    console.log(`  ✓ ${d}`);
  }

  console.log("");
  console.log("Phase summary:");
  for (const phase of result.phases) {
    const status = phase.success ? "PASS" : "FAIL";
    const icon = phase.success ? "✓" : "✗";
    console.log(`  [${status}] ${icon} ${phase.phaseName} — ${phase.deliverables.length} deliverable(s)`);
    for (const err of phase.errors) {
      console.log(`         Error: ${err}`);
    }
  }

  // Agent execution stats
  if (result.agentStats.length > 0) {
    console.log("");
    console.log("═".repeat(72));
    console.log("  Agent Execution Summary");
    console.log("═".repeat(72));
    console.log(`  ${"Agent".padEnd(28)} ${"Status".padStart(6)}  ${"Turns".padStart(5)}  ${"Cost".padStart(8)}  ${"Duration".padStart(10)}`);
    console.log("  " + "-".repeat(68));
    for (const s of result.agentStats) {
      console.log(`  ${s.agentName.padEnd(28)} ${s.status.padStart(6)}  ${String(s.turns).padStart(5)}  $${s.costUsd.toFixed(4).padStart(7)}  ${s.durationSeconds.toFixed(1).padStart(9)}s`);
    }
    console.log("═".repeat(72));
  }

  if (result.totalCostUsd > 0) {
    console.log(`\n  Total API cost: $${result.totalCostUsd.toFixed(4)}`);
  }

  // Deliverable verification
  console.log("");
  const outputDir = path.resolve("deliverables");
  const { found, missing } = verifyDeliverables(outputDir);
  if (found.length > 0) {
    console.log(`Verified deliverables on disk: ${found.length}`);
    for (const f of found) {
      console.log(`  ✓ ${f}`);
    }
  }
  if (missing.length > 0) {
    console.log(`Missing deliverables: ${missing.length}`);
    for (const m of missing) {
      console.log(`  ✗ ${m}`);
    }
  }

  console.log("");
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const cliArgs = parseArgs(process.argv.slice(2));
  if (!cliArgs) {
    process.exit(1);
  }

  printBanner(cliArgs);

  const startTs = Date.now();

  try {
    console.log("Starting pipeline...\n");

    const result = await runPipeline({
      targetUrl: cliArgs.url,
      repoPath: cliArgs.repo,
      verbose: cliArgs.verbose,
      apiKey: cliArgs.apiKey,
      outputDir: cliArgs.output,
      maxRetries: cliArgs.retries,
      maxBudgetUsd: cliArgs.budget,
      replay: cliArgs.replay,
      resumeFrom: cliArgs.resumeFrom,
      onOutput: (line) => {
        if (cliArgs.verbose) {
          console.log(`  [py] ${line}`);
        }
      },
    });

    printResult(result);

    // Exit with non-zero if any phase failed
    const allPassed = result.phases.every((p) => p.success);
    process.exit(allPassed ? 0 : 1);
  } catch (err: unknown) {
    const elapsed = (Date.now() - startTs) / 1000;
    console.error(`\nPipeline failed after ${formatDuration(elapsed)}`);
    if (err instanceof Error) {
      console.error(`  Error: ${err.message}`);
    } else {
      console.error(`  Error: ${String(err)}`);
    }
    process.exit(2);
  }
}

main();
