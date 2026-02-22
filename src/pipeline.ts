/**
 * SPAIDER Agent — Pipeline Orchestrator
 * 
 * Executes the 4-phase pentest pipeline with:
 * - Sequential phase execution (phases depend on previous outputs)
 * - Optional parallel agent execution within phases (with guards)
 * - Comprehensive error handling (phase-level try/catch)
 * - Progress callbacks for GUI integration
 * - Race condition prevention through:
 *   1. Phase-level mutex (only one phase runs at a time)
 *   2. Atomic file writes for deliverables
 *   3. Read-only access to previous phase outputs
 *   4. Separate output files per agent (no write conflicts)
 */

import * as path from 'path';
import * as fs from 'fs';
import {
  PipelineConfig,
  PipelineResult,
  PhaseResult,
  PhaseState,
  AgentConfig,
  AgentResult,
  WSMessage,
  MessageType,
} from './types';
import { runAgent } from './agent-runner';
import { readDeliverable, ensureDir, log, formatDuration } from './utils';

/** Pipeline execution lock — prevents concurrent pipeline runs */
let pipelineRunning = false;

/** Progress callback type for GUI integration */
type ProgressCallback = (message: WSMessage) => void;

/**
 * Emit a progress event to the GUI.
 */
function emitProgress(
  callback: ProgressCallback | undefined,
  type: MessageType,
  data: Record<string, unknown>
): void {
  if (callback) {
    callback({ type, timestamp: Date.now(), data });
  }
}

/**
 * Run a single pipeline phase with error isolation.
 * Each phase is wrapped in try/catch so failures don't cascade.
 */
async function runPhase(
  phaseName: string,
  agents: AgentConfig[],
  outputDir: string,
  parallel: boolean,
  onProgress?: ProgressCallback
): Promise<PhaseResult> {
  const startTime = Date.now();

  emitProgress(onProgress, MessageType.PHASE_START, {
    phaseName,
    agentCount: agents.length,
    parallel,
  });

  log(`━━━ Phase: ${phaseName} (${agents.length} agent(s), ${parallel ? 'parallel' : 'sequential'}) ━━━`);

  try {
    let agentResults: AgentResult[];

    if (parallel && agents.length > 1) {
      // Parallel execution — each agent writes to separate files
      // Safe because:
      // 1. Each agent has unique output filenames
      // 2. Atomic writes prevent partial reads
      // 3. Agents only READ shared inputs (recon data)
      log(`  Running ${agents.length} agents in parallel...`);
      agentResults = await Promise.all(
        agents.map(agent => {
          emitProgress(onProgress, MessageType.AGENT_START, {
            agentName: agent.name,
            phaseName,
          });
          return runAgent(agent, outputDir);
        })
      );
    } else {
      // Sequential execution — safer default
      agentResults = [];
      for (const agent of agents) {
        emitProgress(onProgress, MessageType.AGENT_START, {
          agentName: agent.name,
          phaseName,
        });
        const result = await runAgent(agent, outputDir);
        agentResults.push(result);

        emitProgress(onProgress, MessageType.AGENT_COMPLETE, {
          agentName: agent.name,
          phaseName,
          success: result.success,
          duration: result.duration,
        });
      }
    }

    const endTime = Date.now();
    const allSucceeded = agentResults.every(r => r.success);
    const state = allSucceeded ? PhaseState.COMPLETED : PhaseState.FAILED;

    const result: PhaseResult = {
      phaseName,
      state,
      agentResults,
      startTime,
      endTime,
      error: allSucceeded
        ? undefined
        : agentResults
            .filter(r => !r.success)
            .map(r => `${r.agentName}: ${r.error}`)
            .join('; '),
    };

    emitProgress(onProgress, MessageType.PHASE_COMPLETE, {
      phaseName,
      state,
      duration: endTime - startTime,
    });

    log(`  Phase ${phaseName}: ${state} (${formatDuration(endTime - startTime)})`);
    return result;
  } catch (error) {
    const endTime = Date.now();
    const errorMessage = error instanceof Error ? error.message : String(error);

    log(`  Phase ${phaseName}: FAILED — ${errorMessage}`, 'ERROR');

    emitProgress(onProgress, MessageType.PHASE_COMPLETE, {
      phaseName,
      state: PhaseState.FAILED,
      error: errorMessage,
    });

    return {
      phaseName,
      state: PhaseState.FAILED,
      agentResults: [],
      startTime,
      endTime,
      error: errorMessage,
    };
  }
}

/**
 * Copy pre-computed deliverables for replay mode.
 * This is a safety net for live demos.
 */
function replayDeliverables(outputDir: string): PipelineResult {
  const backupDir = path.join(path.dirname(outputDir), 'deliverables-backup');
  const startTime = Date.now();

  if (!fs.existsSync(backupDir)) {
    log('No backup deliverables found for replay mode', 'ERROR');
    return {
      phases: [],
      totalDuration: 0,
      totalCost: 0,
      findingsCount: 0,
      success: false,
    };
  }

  ensureDir(outputDir);
  const files = fs.readdirSync(backupDir);
  for (const file of files) {
    if (!file.startsWith('.')) {
      fs.copyFileSync(
        path.join(backupDir, file),
        path.join(outputDir, file)
      );
    }
  }

  log(`Replay mode: copied ${files.length} deliverables from backup`);

  return {
    phases: [],
    totalDuration: Date.now() - startTime,
    totalCost: 0,
    findingsCount: files.filter(f => f.startsWith('findings_')).length,
    success: true,
  };
}

/**
 * Run the full pentest pipeline.
 * 
 * Pipeline phases (sequential — each depends on previous output):
 * 1. Recon — source code analysis + network reconnaissance
 * 2. Analysis — hypothesis generation (injection + XSS, can run in parallel)
 * 3. Exploitation — prove vulnerabilities (injection + XSS, can run in parallel)
 * 4. Report — consolidate findings into professional report
 * 
 * Race condition guards:
 * - Pipeline lock prevents concurrent runs
 * - Phase-level try/catch prevents cascade failures
 * - Atomic file writes prevent corruption
 * - Parallel agents write to separate files
 */
export async function runPipeline(
  config: PipelineConfig,
  onProgress?: ProgressCallback
): Promise<PipelineResult> {
  // Guard: prevent concurrent pipeline runs
  if (pipelineRunning) {
    throw new Error('Pipeline is already running. Only one pipeline can execute at a time.');
  }

  pipelineRunning = true;
  const startTime = Date.now();
  const phases: PhaseResult[] = [];
  const promptsDir = path.join(__dirname, 'prompts');

  emitProgress(onProgress, MessageType.PIPELINE_START, {
    targetUrl: config.targetUrl,
    repoPath: config.repoPath,
  });

  try {
    // Replay mode — skip agents, use pre-computed results
    if (config.replay) {
      return replayDeliverables(config.outputDir);
    }

    ensureDir(config.outputDir);

    // ═══════════════════════════════════════════════════
    // PHASE 0: Reconnaissance
    // ═══════════════════════════════════════════════════
    const reconResult = await runPhase(
      'Reconnaissance',
      [
        {
          name: 'recon',
          promptFile: path.join(promptsDir, 'recon.md'),
          vars: {
            TARGET_URL: config.targetUrl,
            REPO_PATH: config.repoPath,
          },
          maxTurns: 50,
          maxBudgetUsd: 4.0,
        },
      ],
      config.outputDir,
      false, // Sequential — only one agent
      onProgress
    );
    phases.push(reconResult);

    // Read recon output for next phase (read-only — safe)
    const reconData = readDeliverable('recon_report.md', config.outputDir) || 'No recon data available.';

    // ═══════════════════════════════════════════════════
    // PHASE 1: Analysis (injection + XSS in parallel)
    // Safe for parallel: each agent reads reconData (immutable)
    // and writes to separate files (hypotheses_injection.md vs hypotheses_xss.md)
    // ═══════════════════════════════════════════════════
    const analysisResult = await runPhase(
      'Analysis',
      [
        {
          name: 'analysis-injection',
          promptFile: path.join(promptsDir, 'analysis-injection.md'),
          vars: { RECON_DATA: reconData },
          maxTurns: 30,
          maxBudgetUsd: 4.0,
        },
        {
          name: 'analysis-xss',
          promptFile: path.join(promptsDir, 'analysis-xss.md'),
          vars: { RECON_DATA: reconData },
          maxTurns: 30,
          maxBudgetUsd: 4.0,
        },
      ],
      config.outputDir,
      true, // Parallel — safe (separate output files)
      onProgress
    );
    phases.push(analysisResult);

    // Read analysis outputs for next phase
    const hypothesesInjection =
      readDeliverable('hypotheses_injection.md', config.outputDir) || 'No injection hypotheses available.';
    const hypothesesXss =
      readDeliverable('hypotheses_xss.md', config.outputDir) || 'No XSS hypotheses available.';

    // ═══════════════════════════════════════════════════
    // PHASE 2: Exploitation (injection + XSS in parallel)
    // Safe for parallel: each agent reads separate hypothesis files
    // and writes to separate findings files.
    // NOTE: Playwright sessions are isolated per agent.
    // ═══════════════════════════════════════════════════
    const exploitResult = await runPhase(
      'Exploitation',
      [
        {
          name: 'exploit-injection',
          promptFile: path.join(promptsDir, 'exploit-injection.md'),
          vars: {
            HYPOTHESES: hypothesesInjection,
            TARGET_URL: config.targetUrl,
          },
          maxTurns: 80,
          maxBudgetUsd: 4.0,
        },
        {
          name: 'exploit-xss',
          promptFile: path.join(promptsDir, 'exploit-xss.md'),
          vars: {
            HYPOTHESES: hypothesesXss,
            TARGET_URL: config.targetUrl,
          },
          maxTurns: 80,
          maxBudgetUsd: 4.0,
        },
      ],
      config.outputDir,
      true, // Parallel — safe (separate files, isolated Playwright sessions)
      onProgress
    );
    phases.push(exploitResult);

    // Read all findings for report phase
    const findingsInjection =
      readDeliverable('findings_injection.md', config.outputDir) || 'No injection findings.';
    const findingsXss =
      readDeliverable('findings_xss.md', config.outputDir) || 'No XSS findings.';
    const allFindings = `# Injection Findings\n\n${findingsInjection}\n\n# XSS Findings\n\n${findingsXss}`;

    // ═══════════════════════════════════════════════════
    // PHASE 3: Report Generation
    // Sequential — single agent, reads all findings (read-only)
    // ═══════════════════════════════════════════════════
    const reportResult = await runPhase(
      'Report',
      [
        {
          name: 'report',
          promptFile: path.join(promptsDir, 'report.md'),
          vars: { FINDINGS: allFindings },
          maxTurns: 20,
          maxBudgetUsd: 4.0,
        },
      ],
      config.outputDir,
      false, // Sequential — only one agent
      onProgress
    );
    phases.push(reportResult);

    // Calculate totals
    const totalDuration = Date.now() - startTime;
    const totalCost = phases.reduce(
      (sum, p) => sum + p.agentResults.reduce((s, r) => s + r.cost, 0),
      0
    );
    const findingsCount =
      (findingsInjection !== 'No injection findings.' ? 1 : 0) +
      (findingsXss !== 'No XSS findings.' ? 1 : 0);

    const result: PipelineResult = {
      phases,
      totalDuration,
      totalCost,
      findingsCount,
      success: phases.some(p => p.state === PhaseState.COMPLETED),
    };

    emitProgress(onProgress, MessageType.PIPELINE_COMPLETE, {
      totalDuration,
      totalCost,
      findingsCount,
      success: result.success,
    });

    log(`\n═══ Pipeline Complete ═══`);
    log(`  Duration: ${formatDuration(totalDuration)}`);
    log(`  Cost: $${totalCost.toFixed(2)}`);
    log(`  Findings: ${findingsCount}`);

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log(`Pipeline failed: ${errorMessage}`, 'ERROR');

    emitProgress(onProgress, MessageType.PIPELINE_ERROR, {
      error: errorMessage,
    });

    return {
      phases,
      totalDuration: Date.now() - startTime,
      totalCost: 0,
      findingsCount: 0,
      success: false,
    };
  } finally {
    pipelineRunning = false;
  }
}
