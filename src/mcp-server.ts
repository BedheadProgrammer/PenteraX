/**
 * SPAIDER Agent — MCP Server
 * 
 * In-process MCP server providing the `save_deliverable` tool
 * for agents to write structured output files. Uses atomic writes
 * to prevent corruption during parallel execution.
 */

import * as path from 'path';
import { saveDeliverable } from './utils';

/** MCP tool definition for save_deliverable */
export interface SaveDeliverableTool {
  name: 'save_deliverable';
  description: string;
  inputSchema: {
    type: 'object';
    properties: {
      name: { type: 'string'; description: string };
      content: { type: 'string'; description: string };
    };
    required: ['name', 'content'];
  };
}

/** MCP server configuration */
export interface McpServerConfig {
  outputDir: string;
  agentName: string;
  phase: string;
}

/**
 * Create the save_deliverable tool definition for MCP registration.
 */
export function createSaveDeliverableTool(): SaveDeliverableTool {
  return {
    name: 'save_deliverable',
    description:
      'Save a deliverable file (e.g., recon_report.md, hypotheses_injection.md). ' +
      'The file will be written atomically to the deliverables directory.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Filename for the deliverable (e.g., recon_report.md)',
        },
        content: {
          type: 'string',
          description: 'Full content of the deliverable file',
        },
      },
      required: ['name', 'content'],
    },
  };
}

/**
 * Handle the save_deliverable tool invocation.
 * Validates input, sanitizes filename, and writes atomically.
 * 
 * @param input - Tool invocation input
 * @param config - MCP server configuration
 * @returns Success/failure response
 */
export async function handleSaveDeliverable(
  input: { name: string; content: string },
  config: McpServerConfig
): Promise<{ success: boolean; path: string; error?: string }> {
  try {
    // Sanitize filename — prevent path traversal and reject dangerous names
    const safeName = path.basename(input.name);
    if (safeName !== input.name || safeName === '..' || safeName === '.') {
      return {
        success: false,
        path: '',
        error: `Invalid filename: ${input.name}. Must be a simple filename without path separators.`,
      };
    }

    const filePath = path.join(config.outputDir, safeName);

    await saveDeliverable(
      safeName,
      input.content,
      config.outputDir,
      { phase: config.phase, agentName: config.agentName }
    );

    return { success: true, path: filePath };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { success: false, path: '', error: errorMessage };
  }
}

/**
 * Create the MCP server configuration for use with Claude Agent SDK.
 * 
 * In production, this would return an McpServer instance that can be
 * passed to the query() function. For now, it returns the config
 * needed to set up the server.
 */
export function createMcpServerConfig(
  outputDir: string,
  agentName: string,
  phase: string
): McpServerConfig {
  return { outputDir, agentName, phase };
}
