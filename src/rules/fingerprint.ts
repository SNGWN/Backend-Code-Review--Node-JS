import * as crypto from 'crypto';
import * as path from 'path';
import { Finding } from '../types';

/**
 * Stable, content-addressed fingerprint for a finding.
 *
 * Inputs:
 *   - ruleId            — drives rule identity
 *   - normalized path   — forward-slash, relative to cwd
 *   - line number       — included so two DISTINCT findings of the same rule with the same code
 *                         snippet on different lines stay distinct. Excluding it (the previous
 *                         behaviour) collapsed sibling sinks to one fingerprint and let a baseline
 *                         entry for one silently suppress the other (a real false-negative).
 *   - normalized code   — whitespace-collapsed snippet (insensitive to formatting changes)
 *
 * Trade-off: a finding that shifts to a new line gets a new fingerprint, so adding/removing lines
 * above it churns the baseline entry. That one-time re-baseline cost is preferred over silently
 * hiding a real vulnerability. (Log-review findings pass no line and are unaffected.)
 */
export function computeFingerprint(finding: Pick<Finding, 'ruleId' | 'file' | 'code' | 'title' | 'category'> & { line?: number }): string {
  const ruleId = finding.ruleId ?? `LEGACY:${finding.category}:${finding.title}`;
  const filePath = normalizePath(finding.file);
  const linePart = typeof finding.line === 'number' ? String(finding.line) : '';
  const code = normalizeCode(finding.code);
  const payload = `${ruleId}\0${filePath}\0${linePart}\0${code}`;
  return crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

export function normalizePath(filePath: string): string {
  const relative = path.isAbsolute(filePath)
    ? path.relative(process.cwd(), filePath)
    : filePath;
  return relative.split(path.sep).join('/');
}

export function normalizeCode(code: string): string {
  return code.replace(/\s+/g, ' ').trim();
}

/**
 * Deterministic POC identifier. POC IDs are SARIF-stable across runs and safe to use
 * as filenames. Inputs: a prefix label, a file path (normalized), a line number, and
 * the vulnerable code snippet.
 */
export function computePocId(prefix: string, filePath: string, line: number, code: string): string {
  const payload = `${prefix}\0${normalizePath(filePath)}\0${line}\0${normalizeCode(code)}`;
  const hash = crypto.createHash('sha256').update(payload).digest('hex').slice(0, 12);
  return `${prefix}-${line}-${hash}`;
}
