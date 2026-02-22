/**
 * SPAIDER Agent — Shared Type Definitions
 * 
 * Central type definitions for the pipeline, agents, and deliverables.
 * All types are designed to prevent race conditions through:
 * - Immutable configuration objects
 * - Explicit state tracking
 * - Sequential-by-default execution model
 */

/** Agent configuration — immutable once created */
export interface AgentConfig {
  readonly name: string;
  readonly promptFile: string;
  readonly vars: Record<string, string>;
  readonly maxTurns: number;
  readonly maxBudgetUsd: number;
  readonly timeout?: number; // ms, default 300000 (5 min)
}

/** Result from a single agent execution */
export interface AgentResult {
  readonly agentName: string;
  readonly deliverables: string[];
  readonly cost: number;
  readonly turns: number;
  readonly duration: number; // ms
  readonly success: boolean;
  readonly error?: string;
}

/** Pipeline configuration */
export interface PipelineConfig {
  readonly targetUrl: string;
  readonly repoPath: string;
  readonly outputDir: string;
  readonly verbose: boolean;
  readonly replay: boolean;
}

/** Pipeline phase state — tracks execution to prevent re-entry */
export enum PhaseState {
  PENDING = 'PENDING',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  SKIPPED = 'SKIPPED',
}

/** Individual phase result */
export interface PhaseResult {
  readonly phaseName: string;
  readonly state: PhaseState;
  readonly agentResults: AgentResult[];
  readonly startTime: number;
  readonly endTime: number;
  readonly error?: string;
}

/** Full pipeline execution result */
export interface PipelineResult {
  readonly phases: PhaseResult[];
  readonly totalDuration: number;
  readonly totalCost: number;
  readonly findingsCount: number;
  readonly success: boolean;
}

/** GUI WebSocket message types */
export enum MessageType {
  PIPELINE_START = 'PIPELINE_START',
  PHASE_START = 'PHASE_START',
  PHASE_COMPLETE = 'PHASE_COMPLETE',
  AGENT_START = 'AGENT_START',
  AGENT_COMPLETE = 'AGENT_COMPLETE',
  PIPELINE_COMPLETE = 'PIPELINE_COMPLETE',
  PIPELINE_ERROR = 'PIPELINE_ERROR',
  LOG = 'LOG',
}

/** WebSocket message envelope */
export interface WSMessage {
  readonly type: MessageType;
  readonly timestamp: number;
  readonly data: Record<string, unknown>;
}

/** Deliverable schema for structured handoff between phases */
export interface DeliverableMetadata {
  readonly name: string;
  readonly phase: string;
  readonly agentName: string;
  readonly createdAt: number;
}

/** Lock state for file operations — prevents concurrent writes */
export interface FileLock {
  readonly path: string;
  readonly holder: string;
  readonly acquiredAt: number;
}
