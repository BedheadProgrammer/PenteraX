/**
 * PenteraX — Shared Type Definitions
 *
 * Central type definitions used across the agentic pentest pipeline.
 */

// ── Pipeline Phase Identifiers ──────────────────────────────────────────────

export type PipelinePhase =
  | "recon"
  | "analysis"
  | "exploit"
  | "report";

// ── Severity Levels ─────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

// ── Vulnerability Record ────────────────────────────────────────────────────

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  cwe?: string;
  description: string;
  evidence?: string;
  remediation?: string;
}

// ── Recon Result ────────────────────────────────────────────────────────────

export interface ReconResult {
  target: string;
  timestamp: string;
  openPorts: number[];
  technologies: string[];
  endpoints: string[];
  rawOutput?: string;
}

// ── Exploit Attempt ─────────────────────────────────────────────────────────

export interface ExploitAttempt {
  phase: PipelinePhase;
  vulnerability: Vulnerability;
  payload: string;
  success: boolean;
  response?: string;
  screenshot?: string;
  timestamp: string;
}

// ── Pipeline Configuration ──────────────────────────────────────────────────

export interface PipelineConfig {
  targetUrl: string;
  apiKey: string;
  phases: PipelinePhase[];
  timeout?: number;
  maxRetries?: number;
}

// ── Pipeline Run Result ─────────────────────────────────────────────────────

export interface PipelineResult {
  config: PipelineConfig;
  startTime: string;
  endTime?: string;
  recon?: ReconResult;
  vulnerabilities: Vulnerability[];
  exploits: ExploitAttempt[];
  reportPath?: string;
  status: "running" | "completed" | "failed" | "aborted";
  error?: string;
}

// ── Agent Message ───────────────────────────────────────────────────────────

export interface AgentMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  phase?: PipelinePhase;
}
