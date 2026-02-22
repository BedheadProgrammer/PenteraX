/**
 * SPAIDER Agent — Utility Functions
 * 
 * Provides file I/O, prompt loading, and synchronization primitives
 * to prevent race conditions during parallel agent execution.
 */

import * as fs from 'fs';
import * as path from 'path';
import { FileLock, DeliverableMetadata } from './types';

/** Active file locks — prevents concurrent writes to the same file */
const activeLocks: Map<string, FileLock> = new Map();

/**
 * Acquire a file lock. Blocks concurrent writes to the same path.
 * Uses a spin-wait with backoff to handle contention.
 * 
 * @param filePath - Absolute path to lock
 * @param holder - Identifier of the lock holder (agent name)
 * @param timeoutMs - Maximum wait time before giving up (default: 30s)
 * @returns true if lock acquired, false if timed out
 */
export async function acquireFileLock(
  filePath: string,
  holder: string,
  timeoutMs: number = 30000
): Promise<boolean> {
  const normalizedPath = path.resolve(filePath);
  const startTime = Date.now();
  let backoff = 50; // Start with 50ms backoff

  while (activeLocks.has(normalizedPath)) {
    if (Date.now() - startTime > timeoutMs) {
      console.error(`[LOCK] Timeout acquiring lock for ${normalizedPath} (holder: ${holder})`);
      return false;
    }
    await new Promise(resolve => setTimeout(resolve, backoff));
    backoff = Math.min(backoff * 2, 1000); // Exponential backoff, max 1s
  }

  activeLocks.set(normalizedPath, {
    path: normalizedPath,
    holder,
    acquiredAt: Date.now(),
  });

  return true;
}

/**
 * Release a file lock.
 * @param filePath - Absolute path to unlock
 */
export function releaseFileLock(filePath: string): void {
  const normalizedPath = path.resolve(filePath);
  activeLocks.delete(normalizedPath);
}

/**
 * Write a file atomically with lock protection.
 * Writes to a temp file first, then renames to prevent partial reads.
 * 
 * @param filePath - Target file path
 * @param content - File content
 * @param holder - Lock holder identifier
 */
export async function writeFileAtomic(
  filePath: string,
  content: string,
  holder: string
): Promise<void> {
  const locked = await acquireFileLock(filePath, holder);
  if (!locked) {
    throw new Error(`Failed to acquire lock for ${filePath}`);
  }

  try {
    const dir = path.dirname(filePath);
    ensureDir(dir);

    // Write to temp file first, then rename (atomic on most filesystems)
    const tempPath = `${filePath}.tmp.${Date.now()}`;
    fs.writeFileSync(tempPath, content, 'utf-8');
    fs.renameSync(tempPath, filePath);
  } finally {
    releaseFileLock(filePath);
  }
}

/**
 * Read a file safely, returning null if it doesn't exist.
 * @param filePath - Path to read
 * @returns File content or null
 */
export function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Load a prompt template and substitute {{VAR}} placeholders.
 * 
 * @param promptFile - Path to prompt template file
 * @param vars - Key-value pairs for substitution
 * @returns Processed prompt string
 */
export function loadPrompt(
  promptFile: string,
  vars: Record<string, string>
): string {
  const content = fs.readFileSync(promptFile, 'utf-8');
  
  let result = content;
  for (const [key, value] of Object.entries(vars)) {
    const placeholder = `{{${key}}}`;
    result = result.split(placeholder).join(value);
  }
  
  return result;
}

/**
 * Ensure a directory exists, creating it recursively if needed.
 * @param dirPath - Directory path
 */
export function ensureDir(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

/**
 * Read a deliverable file from the output directory.
 * @param name - Deliverable filename
 * @param outputDir - Deliverables directory path
 * @returns File content or null
 */
export function readDeliverable(name: string, outputDir: string): string | null {
  const filePath = path.join(outputDir, name);
  return readFileSafe(filePath);
}

/**
 * Save a deliverable with metadata tracking.
 * Uses atomic write to prevent corruption from parallel agents.
 */
export async function saveDeliverable(
  name: string,
  content: string,
  outputDir: string,
  metadata: Omit<DeliverableMetadata, 'name' | 'createdAt'>
): Promise<void> {
  const filePath = path.join(outputDir, name);
  await writeFileAtomic(filePath, content, metadata.agentName);

  // Save metadata alongside deliverable
  const meta: DeliverableMetadata = {
    name,
    ...metadata,
    createdAt: Date.now(),
  };
  const metaPath = path.join(outputDir, `.${name}.meta.json`);
  await writeFileAtomic(metaPath, JSON.stringify(meta, null, 2), metadata.agentName);
}

/**
 * Format duration in milliseconds to human-readable string.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}

/**
 * Get a timestamp string for logging.
 */
export function timestamp(): string {
  return new Date().toISOString();
}

/**
 * Log with timestamp prefix.
 */
export function log(message: string, level: 'INFO' | 'WARN' | 'ERROR' = 'INFO'): void {
  const ts = timestamp();
  const prefix = level === 'ERROR' ? '❌' : level === 'WARN' ? '⚠️' : 'ℹ️';
  console.log(`[${ts}] ${prefix} ${message}`);
}
