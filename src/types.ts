import { ProofOfConcept } from './poc/types';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/**
 * How sure the scanner is that a finding is a real, exploitable issue — orthogonal to severity
 * (which is the impact IF real). Lets the tool *surface* uncertain findings with context instead
 * of silently dropping them, so a human decides.
 *   - CONFIRMED: data-flow / structural evidence ties attacker input to the sink with no guard.
 *   - FIRM:      a strong, specific signal but one unverified link (e.g. a dangerous API on
 *                likely-tainted input, or a request DTO that *may* be validated by a pipe).
 *   - TENTATIVE: a weak/heuristic signal worth a human look — reported, never auto-suppressed.
 */
export type Confidence = 'CONFIRMED' | 'FIRM' | 'TENTATIVE';
export type IssueCategory =
  | 'AUTHENTICATION'
  | 'VALIDATION'
  | 'LOGGING'
  | 'MASS_ASSIGNMENT'
  | 'ACCESS_CONTROL'
  | 'RATE_LIMITING'
  | 'BUSINESS_LOGIC'
  | 'API_KEY_EXPOSURE'
  | 'CRYPTO_WEAKNESS'
  | 'DATA_EXPOSURE'
  | 'CACHE_POISONING'
  | 'MESSAGE_QUEUE'
  | 'EVENT_STREAM'
  | 'SSRF'
  | 'PATH_TRAVERSAL'
  | 'OPEN_REDIRECT'
  | 'MISCONFIGURATION'
  // Log-review categories (mode=logs).
  | 'LOG_PCI'
  | 'LOG_PII'
  | 'LOG_SECRET'
  | 'LOG_OPS';

export type RuntimeIssueType =
  | 'INVALID_TARGET'
  | 'PARSE_FAILURE'
  | 'DETECTOR_FAILURE'
  | 'POC_EXPORT_FAILURE'
  | 'REPORT_WRITE_FAILURE'
  | 'FATAL_ANALYSIS_FAILURE';

export type RuntimeIssueSeverity = 'ERROR' | 'WARNING';

export interface RuntimeIssue {
  type: RuntimeIssueType;
  severity: RuntimeIssueSeverity;
  message: string;
  file?: string;
  detector?: string;
  outputPath?: string;
}

export interface Finding {
  /**
   * Stable rule identifier (e.g. "BCR-AUTH-002"). Optional during the transition —
   * detectors are expected to populate it; the analyzer back-fills via the rule registry
   * for legacy emit paths.
   */
  ruleId?: string;
  category: IssueCategory;
  severity: Severity;
  /**
   * Confidence that this finding is real/exploitable. Optional on emit — the analyzer back-fills
   * from the rule registry (heuristic rules → TENTATIVE, otherwise FIRM) when a detector does not
   * set it. Detectors that confirm a taint flow end-to-end set CONFIRMED.
   */
  confidence?: Confidence;
  /**
   * Optional reviewer guidance attached to lower-confidence findings: what to check to confirm or
   * dismiss. Surfaced so the user can decide rather than the tool silently suppressing.
   */
  verify?: string;
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  code: string;
  recommendation: string;
  /**
   * Stable content fingerprint: sha256(ruleId + normalized-path + normalized-code), truncated.
   * Used by baseline suppression and SARIF partialFingerprints. Populated by the analyzer
   * after detectors run; detectors do not set this.
   */
  fingerprint?: string;
  cwe?: string[];
  owasp?: string;
  /**
   * Set when a suppression matched this finding. Suppressed findings are excluded from
   * the report by default; surfaced via `--show-suppressed`.
   */
  suppressed?: {
    source: 'baseline' | 'inline';
    reason?: string;
  };
  poc?: ProofOfConcept;
  injectionType?: string;
  /**
   * Log-review evidence. Populated only by the log scanner (mode=logs). Carries the
   * Kibana / ES document identity so reviewers can deep-link from a finding back to the
   * exact log entry.
   */
  logEvidence?: {
    docId: string;
    index: string;
    timestamp: string;
    container?: string;
    kibanaUrl?: string;
    /** Excerpt of the log line around the match. NEVER the full line — PCI/PII redaction. */
    excerpt: string;
  };
}

export interface AnalysisReport {
  timestamp: string;
  filesAnalyzed: number;
  totalFindings: number;
  findingsByCategory: Record<IssueCategory, number>;
  findingsBySeverity: Record<Severity, number>;
  /** Per-confidence counts (CONFIRMED / FIRM / TENTATIVE). Helps triage "act now" vs "review". */
  findingsByConfidence?: Record<Confidence, number>;
  /**
   * Per-rule firing counts. PCI-DSS Req 10 evidence asks for "how many findings
   * per rule" cross-referenced with the rule catalog — this is the answer.
   */
  findingsByRule: Record<string, number>;
  findings: Finding[];
  runtimeIssues: RuntimeIssue[];
  runtimeIssuesByType: Record<RuntimeIssueType, number>;
  hasRuntimeErrors: boolean;
}

export interface DetectorResult {
  findings: Finding[];
}

export interface FileInfo {
  path: string;
  content: string;
  ast?: unknown;
}
