import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../types';
import { computeFingerprint, normalizePath } from './fingerprint';

/**
 * Baseline file schema (v1).
 *
 * Persisted JSON of known findings the AppSec team has triaged and accepted as
 * "won't fix" or "tracked elsewhere". Future scans drop anything matching a baseline
 * entry. Match is by fingerprint, which is content-addressed (rule + path + normalized
 * snippet) so trivial diffs don't churn the baseline.
 */
export interface BaselineEntryV1 {
  fingerprint: string;
  ruleId: string;
  file: string;
  reason?: string;
  /**
   * ISO-8601 timestamp the entry was added. Informational only.
   */
  addedAt?: string;
}

export interface BaselineFileV1 {
  version: 1;
  generatedAt: string;
  entries: BaselineEntryV1[];
}

export class Baseline {
  private fingerprints: Map<string, BaselineEntryV1> = new Map();
  private filePath: string | null = null;
  private loaded = false;

  constructor(filePath?: string) {
    if (filePath) {
      this.filePath = path.resolve(filePath);
      this.load();
    }
  }

  /**
   * Returns the baseline entry matching this finding, if any.
   */
  match(finding: Finding): BaselineEntryV1 | undefined {
    if (!this.loaded || !finding.fingerprint) {
      return undefined;
    }
    return this.fingerprints.get(finding.fingerprint);
  }

  /**
   * Snapshots the given findings to disk as a baseline file.
   *
   * Deterministic: two consecutive `--update-baseline` runs on the same source produce
   * BYTE-IDENTICAL output. Previously this wrote `generatedAt` and per-entry `addedAt`
   * timestamps, so committed baselines churned on every CI run. The file format keeps
   * the timestamps as fields but they default to the empty string when produced by
   * `write()`; an old baseline with timestamps still loads cleanly via `match()`.
   */
  static write(filePath: string, findings: Finding[]): void {
    const seen = new Set<string>();
    const entries: BaselineEntryV1[] = [];

    for (const finding of findings) {
      const fingerprint = finding.fingerprint ?? computeFingerprint(finding);
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);
      entries.push({
        fingerprint,
        ruleId: finding.ruleId ?? `LEGACY:${finding.category}:${finding.title}`,
        file: normalizePath(finding.file),
      });
    }

    entries.sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));

    const payload: BaselineFileV1 = {
      version: 1,
      // Omitted intentionally; presence-of-the-file is the audit signal.
      generatedAt: '',
      entries,
    };

    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', 'utf-8');
  }

  private load(): void {
    if (!this.filePath) return;
    if (!fs.existsSync(this.filePath)) {
      throw new Error(`Baseline file ${this.filePath} does not exist`);
    }

    const raw = fs.readFileSync(this.filePath, 'utf-8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`Baseline file ${this.filePath} is not valid JSON: ${(error as Error).message}`);
    }

    if (!parsed || typeof parsed !== 'object') {
      throw new Error(`Baseline file ${this.filePath} is malformed`);
    }

    const candidate = parsed as Partial<BaselineFileV1>;
    if (candidate.version !== 1 || !Array.isArray(candidate.entries)) {
      throw new Error(`Baseline file ${this.filePath} is not version 1 (entries[])`);
    }

    for (const entry of candidate.entries) {
      if (entry && typeof entry.fingerprint === 'string') {
        this.fingerprints.set(entry.fingerprint, entry);
      }
    }
    this.loaded = true;
  }
}

/**
 * Inline suppression scanner.
 *
 * Two syntaxes (both case-sensitive on the marker text, case-insensitive on rule ids):
 *   // bcr-disable-next-line RULE_ID[,RULE_ID] -- reason
 *   // bcr-disable-line RULE_ID[,RULE_ID] -- reason
 *
 * `RULE_ID` may also be `*` to suppress every rule on the line. Multiple comma-separated
 * ids are supported.
 *
 * The scanner returns a map from 1-based line number to the set of suppressed rule ids
 * effective for that line.
 */
export interface InlineSuppression {
  ruleIds: Set<string>;
  reason: string | undefined;
}

export function buildInlineSuppressions(fileContent: string): Map<number, InlineSuppression> {
  const lines = fileContent.split(/\r?\n/);
  const suppressions = new Map<number, InlineSuppression>();

  const captureNextLine = /\/\/\s*bcr-disable-next-line\s+([A-Za-z0-9_,\-*]+)(?:\s*--\s*(.*))?/;
  const captureLine = /\/\/\s*bcr-disable-line\s+([A-Za-z0-9_,\-*]+)(?:\s*--\s*(.*))?/;

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    const nextMatch = captureNextLine.exec(line);
    if (nextMatch) {
      attach(suppressions, lineNumber + 1, nextMatch[1], nextMatch[2]);
    }

    const sameMatch = captureLine.exec(line);
    if (sameMatch) {
      attach(suppressions, lineNumber, sameMatch[1], sameMatch[2]);
    }
  });

  return suppressions;
}

function attach(
  store: Map<number, InlineSuppression>,
  lineNumber: number,
  rulesField: string,
  reason: string | undefined
): void {
  const ids = rulesField.split(',').map((id) => id.trim().toUpperCase()).filter(Boolean);
  if (ids.length === 0) return;

  const existing = store.get(lineNumber);
  if (existing) {
    ids.forEach((id) => existing.ruleIds.add(id));
    if (reason && !existing.reason) {
      existing.reason = reason.trim();
    }
    return;
  }

  store.set(lineNumber, {
    ruleIds: new Set(ids),
    reason: reason?.trim(),
  });
}

export function isLineSuppressed(
  suppressions: Map<number, InlineSuppression>,
  lineNumber: number,
  ruleId: string | undefined
): { suppressed: boolean; reason?: string } {
  const entry = suppressions.get(lineNumber);
  if (!entry) return { suppressed: false };

  if (entry.ruleIds.has('*')) {
    return { suppressed: true, reason: entry.reason };
  }

  if (ruleId && entry.ruleIds.has(ruleId.toUpperCase())) {
    return { suppressed: true, reason: entry.reason };
  }

  return { suppressed: false };
}
