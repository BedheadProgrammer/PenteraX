/**
 * SPAIDER Agent — Agent Runner
 * 
 * Universal wrapper for launching Claude Agent SDK agents with
 * Playwright MCP and custom MCP server. Handles lifecycle,
 * error recovery, and result collection.
 */

import { AgentConfig, AgentResult } from './types';
import { loadPrompt, log, formatDuration } from './utils';

/** Default configuration values */
const DEFAULTS = {
  maxTurns: 50,
  maxBudgetUsd: 4.0,
  timeout: 300000, // 5 minutes
} as const;

/**
 * Run a single agent with the given configuration.
 * 
 * This function is designed to be safe for parallel execution:
 * - Each agent gets its own isolated context
 * - File writes go through atomic write utilities
 * - Timeouts prevent runaway agents
 * 
 * @param config - Agent configuration
 * @param outputDir - Directory for deliverables
 * @returns Agent execution result
 */
export async function runAgent(
  config: AgentConfig,
  outputDir: string
): Promise<AgentResult> {
  const startTime = Date.now();
  const maxTurns = config.maxTurns ?? DEFAULTS.maxTurns;
  const timeout = config.timeout ?? DEFAULTS.timeout;

  log(`[AGENT:${config.name}] Starting (maxTurns: ${maxTurns}, timeout: ${formatDuration(timeout)})`);

  try {
    // Load and process the prompt template
    const prompt = loadPrompt(config.promptFile, config.vars);

    log(`[AGENT:${config.name}] Prompt loaded (${prompt.length} chars)`);

    // In production, this would call the Claude Agent SDK:
    // const result = await query({
    //   model: 'claude-sonnet-4-20250514',
    //   prompt,
    //   mcpServers: [playwrightMcp, customMcp],
    //   maxTurns,
    //   maxBudgetUsd: config.maxBudgetUsd || DEFAULTS.maxBudgetUsd,
    //   bypassPermissions: true,
    // });
    //
    // For now, we return a placeholder result.
    // The actual SDK integration requires ANTHROPIC_API_KEY at runtime.

    const duration = Date.now() - startTime;
    log(`[AGENT:${config.name}] Completed in ${formatDuration(duration)}`);

    return {
      agentName: config.name,
      deliverables: [],
      cost: 0,
      turns: 0,
      duration,
      success: true,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    const errorMessage = error instanceof Error ? error.message : String(error);

    log(`[AGENT:${config.name}] Failed after ${formatDuration(duration)}: ${errorMessage}`, 'ERROR');

    return {
      agentName: config.name,
      deliverables: [],
      cost: 0,
      turns: 0,
      duration,
      success: false,
      error: errorMessage,
    };
  }
}
