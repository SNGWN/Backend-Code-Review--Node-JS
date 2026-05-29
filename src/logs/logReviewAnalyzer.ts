import { AnalysisReport, Finding, RuntimeIssue, Severity } from '../types';
import { JSONReporter } from '../reporter';
import { KibanaClient, SearchOptions } from './kibanaClient';
import { matchToFinding, scanLogLine } from './logRules';
import { computeFingerprint } from '../rules/fingerprint';
import { Baseline } from '../rules/baseline';
import { getRule, isHeuristic, severityAtLeast, severityRank } from '../rules/registry';
import { ExtendedAnalysisReport } from '../analyzer';
import { Logger } from '../utils/logger';

export interface LogReviewOptions {
  containerName: string;
  /** ISO start of the review window. */
  fromIso: string;
  /** ISO end (exclusive). */
  toIso: string;
  includeHeuristics?: boolean;
  minSeverity?: Severity;
  baselinePath?: string;
  disabledRules?: string[];
  maxHits?: number;
}

/**
 * Log-review counterpart to `BackendCodeReviewAnalyzer`. Streams hits from Kibana,
 * scans each line through the rule set, emits a Finding[] in the same shape as the code
 * analyzer so SARIF / baseline / severity threshold logic is shared.
 *
 * Compliance posture (UAE bank-ready):
 *   - PCI-DSS 3.3 redaction: matched substrings are masked in the excerpt; the unmasked
 *     value is hashed into the fingerprint but NEVER persisted in findings or SARIF.
 *   - Deterministic: runs on the same time window produce identical output (fingerprint
 *     dedup + content-addressed ordering).
 *   - Bounded: respects `maxHits` and stops cleanly if the user interrupts.
 */
export class LogReviewAnalyzer {
  private findings: Finding[] = [];
  private suppressedFindings: Finding[] = [];
  private runtimeIssues: RuntimeIssue[] = [];
  private hitsScanned = 0;

  constructor(private client: KibanaClient) {}

  async analyze(options: LogReviewOptions): Promise<ExtendedAnalysisReport> {
    this.findings = [];
    this.suppressedFindings = [];
    this.runtimeIssues = [];
    this.hitsScanned = 0;

    const searchOptions: SearchOptions = {
      containerName: options.containerName,
      from: options.fromIso,
      to: options.toIso,
      maxHits: options.maxHits,
    };

    try {
      for await (const hit of this.client.streamHits(searchOptions)) {
        this.hitsScanned += 1;
        const line = hit.message;
        if (!line) continue;

        const matches = scanLogLine(line);
        for (const match of matches) {
          const deepLink = this.client.buildKibanaDeepLink(hit);
          // Pass ALL matches so the excerpt builder can mask co-located sensitive
          // values, not just the one being reported. PCI-DSS / UAE PDPL invariant.
          const finding = matchToFinding(match, hit, options.containerName, deepLink, matches);
          // Fingerprint over rule + index + matched value (NOT the raw line — fewer
          // PCI artefacts on disk and stabler dedup).
          finding.fingerprint = computeFingerprint({
            ruleId: finding.ruleId,
            file: `${hit._index}/${match.ruleId}/${match.match}`,
            code: '',
            title: finding.title,
            category: finding.category,
          });
          const rule = getRule(finding.ruleId ?? '');
          finding.cwe = rule?.cwe;
          finding.owasp = rule?.owasp;
          this.findings.push(finding);
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.runtimeIssues.push({
        type: 'FATAL_ANALYSIS_FAILURE',
        severity: 'ERROR',
        message: `Log scan failed: ${errorMessage}`,
      });
      Logger.runtimeError(`Log scan failed`, { error: errorMessage });
    }

    return this.buildReport(options);
  }

  private buildReport(options: LogReviewOptions): ExtendedAnalysisReport {
    const visible: Finding[] = [];
    const suppressed: Finding[] = [];
    const includeHeuristics = options.includeHeuristics === true;
    const minSeverity: Severity = options.minSeverity ?? (includeHeuristics ? 'LOW' : 'HIGH');
    const disabledRules = new Set((options.disabledRules ?? []).map((id) => id.toUpperCase()));
    const baseline = options.baselinePath ? new Baseline(options.baselinePath) : null;

    // Dedup by fingerprint — many log lines from the same container repeat the same
    // pattern, and shipping 10k identical PAN findings is unactionable.
    const seenFingerprint = new Set<string>();

    for (const finding of this.findings) {
      if (finding.ruleId && disabledRules.has(finding.ruleId.toUpperCase())) continue;
      const ruleIsHeuristic = finding.ruleId ? isHeuristic(finding.ruleId) : false;
      if (ruleIsHeuristic && !includeHeuristics) continue;
      if (!severityAtLeast(finding.severity, minSeverity)) continue;
      if (finding.fingerprint && seenFingerprint.has(finding.fingerprint)) continue;
      if (finding.fingerprint) seenFingerprint.add(finding.fingerprint);

      if (baseline) {
        const entry = baseline.match(finding);
        if (entry) {
          suppressed.push({ ...finding, suppressed: { source: 'baseline', reason: entry.reason } });
          continue;
        }
      }
      visible.push(finding);
    }

    this.suppressedFindings = suppressed;

    visible.sort((a, b) => {
      const sd = severityRank(b.severity) - severityRank(a.severity);
      if (sd !== 0) return sd;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      const ar = a.ruleId ?? '';
      const br = b.ruleId ?? '';
      return ar < br ? -1 : ar > br ? 1 : 0;
    });

    const base: AnalysisReport = JSONReporter.generateReport(visible, this.hitsScanned, [...this.runtimeIssues]);
    const extended: ExtendedAnalysisReport = { ...base };
    if (this.suppressedFindings.length > 0) {
      extended.suppressedFindings = this.suppressedFindings;
    }
    return extended;
  }
}
