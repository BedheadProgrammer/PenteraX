/**
 * PenteraX — TypeScript Pipeline Orchestrator
 *
 * Thin wrapper that delegates to the Python pipeline (`src.pipeline.run_pipeline`)
 * via a child process. Provides typed interfaces and progress reporting for the
 * TypeScript layer (CLI + future GUI).
 *
 * Phase 3 — Stream A1
 */

import { spawn, type ChildProcess } from "node:child_process";
import * as path from "node:path";
import * as fs from "node:fs";
import type { PipelineConfig, PipelineResult, PipelinePhase } from "./types";

// ── Constants ───────────────────────────────────────────────────────────────

const PROJECT_ROOT = path.resolve(__dirname, "..");
const DELIVERABLES_DIR = path.join(PROJECT_ROOT, "deliverables");

/** Expected deliverables per pipeline phase. */
const PHASE_DELIVERABLES: Record<PipelinePhase, string[]> = {
  recon: ["recon_report.md"],
  analysis: ["hypotheses_injection.md", "hypotheses_xss.md"],
  exploit: ["findings_injection.md", "findings_xss.md"],
  report: ["pentest_report.md"],
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Resolve the Python interpreter — prefer the local venv. */
function findPython(): string {
  const venvPython = path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe");
  if (fs.existsSync(venvPython)) return venvPython;

  const venvPythonUnix = path.join(PROJECT_ROOT, ".venv", "bin", "python");
  if (fs.existsSync(venvPythonUnix)) return venvPythonUnix;

  return "python";
}

/** Check whether a deliverable file exists and is non-empty. */
function deliverableExists(name: string, outputDir: string): boolean {
  const p = path.join(outputDir, name);
  try {
    const stat = fs.statSync(p);
    return stat.size > 0;
  } catch {
    return false;
  }
}

// ── Phase result (mirrors Python PhaseResult) ───────────────────────────────

export interface PhaseResultTS {
  phaseName: string;
  success: boolean;
  deliverables: string[];
  durationSeconds: number;
  errors: string[];
  validationPassed: boolean;
}

/** Per-agent execution statistics parsed from Python stdout. */
export interface AgentStatsTS {
  agentName: string;
  status: string;
  turns: number;
  costUsd: number;
  durationSeconds: number;
}

export interface PipelineResultTS {
  phases: PhaseResultTS[];
  totalDurationSeconds: number;
  deliverablesGenerated: string[];
  /** Per-agent stats (populated when available from Python output). */
  agentStats: AgentStatsTS[];
  totalCostUsd: number;
}

// ── Pipeline runner ─────────────────────────────────────────────────────────

export interface RunPipelineOptions {
  /** Target URL (required). */
  targetUrl: string;
  /** Path to the repo to analyze (required). */
  repoPath: string;
  /** Output directory for deliverables. */
  outputDir?: string;
  /** Enable verbose/debug logging. */
  verbose?: boolean;
  /** Anthropic API key (reads from env if omitted). */
  apiKey?: string;
  /** Max retries per phase. */
  maxRetries?: number;
  /** Max budget in USD. */
  maxBudgetUsd?: number;
  /** Run in replay mode (no API calls). */
  replay?: boolean;
  /** Phase to resume from. */
  resumeFrom?: PipelinePhase;
  /** Called for each stdout line from the Python process. */
  onOutput?: (line: string) => void;
}

/**
 * Run the full PenteraX pipeline by delegating to the Python CLI.
 *
 * Returns a `PipelineResultTS` built from stdout/deliverable-file inspection
 * after the Python process exits.
 */
export function runPipeline(opts: RunPipelineOptions): Promise<PipelineResultTS> {
  return new Promise((resolve, reject) => {
    const python = findPython();
    const outputDir = opts.outputDir ?? DELIVERABLES_DIR;

    // Build command-line arguments for `python -m src --cli pipeline ...`
    const args: string[] = [
      "-m", "src", "--cli",
    ];

    if (opts.verbose) args.push("--verbose");

    args.push("pipeline");
    args.push("--target", opts.targetUrl);

    if (opts.repoPath) args.push("--repo", opts.repoPath);
    if (opts.apiKey) args.push("--api-key", opts.apiKey);
    if (outputDir !== DELIVERABLES_DIR) args.push("--output", outputDir);
    if (opts.maxRetries != null) args.push("--retries", String(opts.maxRetries));
    if (opts.maxBudgetUsd != null) args.push("--budget", String(opts.maxBudgetUsd));
    if (opts.resumeFrom) args.push("--resume-from", opts.resumeFrom);
    if (opts.replay) args.push("--replay");

    const startTime = Date.now();
    const stdout: string[] = [];
    const stderr: string[] = [];

    const child: ChildProcess = spawn(python, args, {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: "1",
        PYTHONIOENCODING: "utf-8",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    child.stdout?.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf-8");
      stdout.push(text);
      if (opts.onOutput) {
        for (const line of text.split("\n").filter(Boolean)) {
          opts.onOutput(line);
        }
      }
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      stderr.push(chunk.toString("utf-8"));
    });

    child.on("error", (err) => {
      reject(new Error(`Failed to start Python pipeline: ${err.message}`));
    });

    child.on("close", (code) => {
      const elapsed = (Date.now() - startTime) / 1000;

      // Build result from deliverable-file inspection
      const result: PipelineResultTS = {
        phases: [],
        totalDurationSeconds: elapsed,
        deliverablesGenerated: [],
        agentStats: [],
        totalCostUsd: 0,
      };

      const phaseOrder: PipelinePhase[] = ["recon", "analysis", "exploit", "report"];

      for (const phase of phaseOrder) {
        const expected = PHASE_DELIVERABLES[phase];
        const found = expected.filter((d) => deliverableExists(d, outputDir));
        const success = found.length > 0;

        result.phases.push({
          phaseName: phase,
          success,
          deliverables: found,
          durationSeconds: 0, // individual timing not available from wrapper
          errors: success ? [] : [`No deliverables found for ${phase}`],
          validationPassed: success,
        });

        result.deliverablesGenerated.push(...found);
      }

      // Parse per-agent stats from stdout (format: "  <name>   <STATUS>  <turns>  $<cost>  <dur>s")
      const allStdout = stdout.join("");
      const statsLineRe = /^\s{2}(\S+)\s+(OK|FAIL)\s+(\d+)\s+\$\s*([\d.]+)\s+([\d.]+)s/gm;
      let match: RegExpExecArray | null;
      while ((match = statsLineRe.exec(allStdout)) !== null) {
        result.agentStats.push({
          agentName: match[1],
          status: match[2],
          turns: parseInt(match[3], 10),
          costUsd: parseFloat(match[4]),
          durationSeconds: parseFloat(match[5]),
        });
      }

      // Parse total cost from stdout (format: "Total API cost: $X.XXXX")
      const costMatch = allStdout.match(/Total API cost:\s+\$([\d.]+)/);
      if (costMatch) {
        result.totalCostUsd = parseFloat(costMatch[1]);
      }

      if (code !== 0 && code !== null) {
        const errText = stderr.join("").trim();
        const lastPhase = result.phases[result.phases.length - 1];
        if (lastPhase && errText) {
          lastPhase.errors.push(errText.slice(0, 500));
        }
      }

      resolve(result);
    });
  });
}

/**
 * Verify all expected deliverables exist on disk.
 *
 * @returns Object with `found` and `missing` arrays.
 */
export function verifyDeliverables(
  outputDir: string = DELIVERABLES_DIR,
): { found: string[]; missing: string[] } {
  const allExpected = Object.values(PHASE_DELIVERABLES).flat();
  const found: string[] = [];
  const missing: string[] = [];

  for (const name of allExpected) {
    if (deliverableExists(name, outputDir)) {
      found.push(name);
    } else {
      missing.push(name);
    }
  }

  return { found, missing };
}
