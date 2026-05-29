import * as ts from 'typescript';
import * as path from 'path';
import * as fs from 'fs';
import {
  AnalysisReport,
  DetectorResult,
  Finding,
  RuntimeIssue,
  Severity,
} from './types';
import { ASTParser } from './parser/astParser';
import { AuthenticationDetector } from './detectors/authDetector';
import { ParameterValidationDetector } from './detectors/validationDetector';
import { LogReviewDetector } from './detectors/logDetector';
import { MassAssignmentDetector } from './detectors/massAssignDetector';
import { RateLimitDetector } from './detectors/rateLimitDetector';
import { AccessControlDetector } from './detectors/accessControlDetector';
import { BusinessLogicDetector } from './detectors/businessLogicDetector';
import { JwtBypassDetector } from './detectors/jwtBypassDetector';
import { ApiKeyDetector } from './detectors/apiKeyDetector';
import { DeserializationDetector } from './detectors/deserializationDetector';
import { CryptoWeaknessDetector } from './detectors/cryptoWeaknessDetector';
import { DataExposureDetector } from './detectors/dataExposureDetector';
import { CachePoisoningDetector } from './detectors/cachePoisoningDetector';
import { MessageQueueDetector } from './detectors/messageQueueDetector';
import { EventStreamDetector } from './detectors/eventStreamDetector';
import { SsrfDetector } from './detectors/ssrfDetector';
import { MisconfigurationDetector } from './detectors/misconfigurationDetector';
import { FileHelper } from './utils/helpers';
import { ProofOfConcept } from './poc/types';
import { PocMarkdownReportGenerator } from './poc/PocMarkdownReportGenerator';
import { JSONReporter } from './reporter';
import { Logger } from './utils/logger';
import { getRule, isHeuristic, severityAtLeast, severityRank } from './rules/registry';
import { computeFingerprint, normalizePath } from './rules/fingerprint';
import { Baseline, buildInlineSuppressions, isLineSuppressed } from './rules/baseline';

interface DetectorWithPocs {
  detect(): DetectorResult;
  getPocs?: () => ProofOfConcept[];
  getGeneratedPocs?: () => ProofOfConcept[];
}

interface DetectorFactory {
  name: string;
  create: (
    filePath: string,
    sourceFile: ts.SourceFile,
    parser: ASTParser
  ) => DetectorWithPocs;
}

export interface AnalysisOptions {
  /**
   * Include heuristic (lower-confidence) rules in the report. When false (default),
   * findings whose ruleId is marked `heuristic: true` in the rule registry are filtered.
   */
  includeHeuristics?: boolean;
  /**
   * Minimum severity threshold for the report. Findings below this severity are dropped.
   * Default: CRITICAL when `--exploitable-only` semantics apply, otherwise LOW.
   */
  minSeverity?: Severity;
  /**
   * Path to a baseline JSON file. Findings matching a baseline entry by fingerprint are
   * suppressed and surfaced under `suppressedFindings`.
   */
  baselinePath?: string;
  /**
   * Explicit list of ruleIds to disable (case-insensitive).
   */
  disabledRules?: string[];
  /**
   * When true, also include suppressed findings in the returned report's
   * `suppressedFindings` (the main `findings` array stays clean).
   */
  showSuppressed?: boolean;
}

/**
 * Extended report shape carrying suppression data the SARIF reporter needs.
 */
export interface ExtendedAnalysisReport extends AnalysisReport {
  suppressedFindings?: Finding[];
}

/**
 * Backend Code Review Analyzer
 *
 * Orchestrates detector execution over TypeScript files, applies rule-registry-based
 * filtering (severity threshold, baseline, inline suppression, heuristic gating), and
 * emits a deterministic, fingerprinted finding stream consumable by JSON, text, or SARIF
 * reporters.
 */
export class BackendCodeReviewAnalyzer {
  private findings: Finding[] = [];
  private suppressedFindings: Finding[] = [];
  private filesAnalyzed = 0;
  private generatedPocs: ProofOfConcept[] = [];
  private runtimeIssues: RuntimeIssue[] = [];
  private analysisOptions: AnalysisOptions = {};
  /**
   * Per-file inline suppression maps. Keyed by absolute file path.
   */
  private inlineSuppressionByFile = new Map<string, Map<number, ReturnType<typeof buildInlineSuppressions> extends Map<number, infer V> ? V : never>>();
  private baseline: Baseline | null = null;
  private detectorFactories: DetectorFactory[] = [
    {
      name: 'AuthenticationDetector',
      create: (filePath, sourceFile, parser) => new AuthenticationDetector(filePath, sourceFile, parser),
    },
    {
      name: 'ParameterValidationDetector',
      create: (filePath, sourceFile, parser) => new ParameterValidationDetector(filePath, sourceFile, parser),
    },
    {
      name: 'LogReviewDetector',
      create: (filePath, sourceFile, parser) => new LogReviewDetector(filePath, sourceFile, parser),
    },
    {
      name: 'MassAssignmentDetector',
      create: (filePath, sourceFile, parser) => new MassAssignmentDetector(filePath, sourceFile, parser),
    },
    {
      name: 'RateLimitDetector',
      create: (filePath, sourceFile, parser) => new RateLimitDetector(filePath, sourceFile, parser),
    },
    {
      name: 'AccessControlDetector',
      create: (filePath, sourceFile, parser) => new AccessControlDetector(filePath, sourceFile, parser),
    },
    {
      name: 'BusinessLogicDetector',
      create: (filePath, sourceFile, parser) => new BusinessLogicDetector(filePath, sourceFile, parser),
    },
    {
      name: 'JwtBypassDetector',
      create: (filePath, sourceFile, parser) => new JwtBypassDetector(filePath, sourceFile, parser),
    },
    {
      name: 'ApiKeyDetector',
      create: (filePath, sourceFile, parser) => new ApiKeyDetector(filePath, sourceFile, parser),
    },
    {
      name: 'DeserializationDetector',
      create: (filePath, sourceFile, parser) => new DeserializationDetector(filePath, sourceFile, parser),
    },
    {
      name: 'CryptoWeaknessDetector',
      create: (filePath, sourceFile, parser) => new CryptoWeaknessDetector(filePath, sourceFile, parser),
    },
    {
      name: 'DataExposureDetector',
      create: (filePath, sourceFile, parser) => new DataExposureDetector(filePath, sourceFile, parser),
    },
    {
      name: 'CachePoisoningDetector',
      create: (filePath, sourceFile, parser) => new CachePoisoningDetector(filePath, sourceFile, parser),
    },
    {
      name: 'MessageQueueDetector',
      create: (filePath, sourceFile, parser) => new MessageQueueDetector(filePath, sourceFile, parser),
    },
    {
      name: 'EventStreamDetector',
      create: (filePath, sourceFile, parser) => new EventStreamDetector(filePath, sourceFile, parser),
    },
    {
      name: 'SsrfDetector',
      create: (filePath, sourceFile, parser) => new SsrfDetector(filePath, sourceFile, parser),
    },
    {
      name: 'MisconfigurationDetector',
      create: (filePath, sourceFile, parser) => new MisconfigurationDetector(filePath, sourceFile, parser),
    },
  ];

  analyze(targetPath: string, options: AnalysisOptions = {}): ExtendedAnalysisReport {
    this.resetState();
    this.analysisOptions = options;
    if (options.baselinePath) {
      try {
        this.baseline = new Baseline(options.baselinePath);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.addRuntimeIssue({
          type: 'FATAL_ANALYSIS_FAILURE',
          severity: 'ERROR',
          message: `Failed to load baseline: ${errorMessage}`,
        });
        Logger.runtimeError(`Failed to load baseline: ${errorMessage}`);
      }
    }

    try {
      const files = this.getTargetFiles(targetPath);

      if (files.length === 0) {
        return this.generateReport();
      }

      Logger.info(`📁 Found ${files.length} TypeScript files to analyze...`);

      for (const filePath of files) {
        this.analyzeFile(filePath);
      }

      return this.generateReport();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.addRuntimeIssue({
        type: 'FATAL_ANALYSIS_FAILURE',
        severity: 'ERROR',
        message: errorMessage,
      });
      Logger.runtimeError('Fatal error during analysis', { error: errorMessage });
      return this.generateReport();
    }
  }

  getPocs(): ProofOfConcept[] {
    const reportFindings = this.getReportFindings();
    return this.generatedPocs.filter((poc) => this.matchesPocToFinding(poc, reportFindings));
  }

  /**
   * Legacy alias for callers that filter findings by "exploitable" classification.
   * Now backed by the rule registry's severity + heuristic flag.
   */
  getExploitableFindings(findings: Finding[] = this.findings): Finding[] {
    return findings.filter((finding) => this.isExploitableFinding(finding));
  }

  exportPocsAsMarkdown(outputDir: string): string[] {
    const exportedFiles: string[] = [];
    const pocs = this.getPocs();

    if (pocs.length === 0) {
      Logger.info('No POCs to export');
      return exportedFiles;
    }

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    pocs.forEach((poc) => {
      try {
        const filePath = PocMarkdownReportGenerator.savePocReport(poc, outputDir);
        exportedFiles.push(filePath);
        Logger.success(`POC exported: ${filePath}`);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.addRuntimeIssue({
          type: 'POC_EXPORT_FAILURE',
          severity: 'ERROR',
          message: `Failed to export POC ${poc.id}: ${errorMessage}`,
          outputPath: outputDir,
        });
        Logger.runtimeError(`Failed to export POC ${poc.id}`, { error: errorMessage });
      }
    });

    return exportedFiles;
  }

  generateComprehensivePocReport(outputPath: string, projectName?: string): string {
    const pocs = this.getPocs();

    if (pocs.length === 0) {
      Logger.warn('No POCs to generate report for');
      return '';
    }

    const summary = {
      projectName,
      analyzedAt: new Date(),
      totalVulnerabilities: pocs.length,
      critical: pocs.filter((p) => p.severity === 'CRITICAL').length,
      high: pocs.filter((p) => p.severity === 'HIGH').length,
      medium: pocs.filter((p) => p.severity === 'MEDIUM').length,
      low: pocs.filter((p) => p.severity === 'LOW').length,
    };

    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    return PocMarkdownReportGenerator.saveComprehensiveReport(pocs, summary, outputPath);
  }

  /**
   * Returns the in-memory finding stream that would feed a baseline (post-fingerprinting,
   * pre-suppression). Exposed for `--update-baseline` callers.
   */
  getAllFindingsWithFingerprints(): Finding[] {
    return [...this.findings];
  }

  private resetState(): void {
    this.findings = [];
    this.suppressedFindings = [];
    this.generatedPocs = [];
    this.filesAnalyzed = 0;
    this.runtimeIssues = [];
    this.inlineSuppressionByFile.clear();
    this.baseline = null;
  }

  private getTargetFiles(targetPath: string): string[] {
    if (FileHelper.isFile(targetPath)) {
      return [targetPath];
    }

    if (FileHelper.isDirectory(targetPath)) {
      return FileHelper.getAllTypeScriptFiles(targetPath, {
        respectGitIgnore: true,
        ignorePatterns: this.getDirectoryIgnorePatterns(targetPath),
      });
    }

    this.addRuntimeIssue({
      type: 'INVALID_TARGET',
      severity: 'ERROR',
      message: `Path not found: ${targetPath}`,
      file: targetPath,
    });
    Logger.runtimeError(`Path not found: ${targetPath}`);
    return [];
  }

  private analyzeFile(filePath: string): void {
    this.filesAnalyzed++;

    const parser = new ASTParser(filePath);
    const sourceFile = parser.parse();

    if (!sourceFile) {
      this.addRuntimeIssue({
        type: 'PARSE_FAILURE',
        severity: 'ERROR',
        message: parser.getLastError() || 'Failed to parse file',
        file: filePath,
      });
      Logger.runtimeWarn(`Skipping ${filePath} - failed to parse`, {
        error: parser.getLastError() || 'syntax error',
      });
      return;
    }

    // Build per-file inline suppressions once — reused by every detector's findings.
    this.inlineSuppressionByFile.set(
      filePath,
      buildInlineSuppressions(sourceFile.getFullText())
    );

    const relPath = path.relative(process.cwd(), filePath);
    Logger.info(`  ✓ ${relPath}`);

    for (const detectorFactory of this.detectorFactories) {
      try {
        const detector = detectorFactory.create(filePath, sourceFile, parser);
        const result = detector.detect();
        this.findings.push(...result.findings);
        this.generatedPocs.push(...this.extractPocs(detector));
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.addRuntimeIssue({
          type: 'DETECTOR_FAILURE',
          severity: 'ERROR',
          message: errorMessage,
          file: filePath,
          detector: detectorFactory.name,
        });
        Logger.runtimeWarn(`Detector ${detectorFactory.name} failed in ${filePath}`, {
          error: errorMessage,
        });
      }
    }
  }

  private extractPocs(detector: DetectorWithPocs): ProofOfConcept[] {
    if (typeof detector.getPocs === 'function') {
      return detector.getPocs();
    }

    if (typeof detector.getGeneratedPocs === 'function') {
      return detector.getGeneratedPocs();
    }

    return [];
  }

  private generateReport(): ExtendedAnalysisReport {
    const reportFindings = this.getReportFindings();
    const baseReport = JSONReporter.generateReport(reportFindings, this.filesAnalyzed, [...this.runtimeIssues]);
    const extended: ExtendedAnalysisReport = { ...baseReport };
    if (this.suppressedFindings.length > 0) {
      extended.suppressedFindings = this.suppressedFindings.map((finding) => this.enrichForReport(finding));
    }
    return extended;
  }

  /**
   * Legacy "exploitable" filter — preserved for back-compat callers. The new gating
   * logic is in `getReportFindings()` (severity threshold + heuristic flag + baseline +
   * inline suppression). This method is now a thin wrapper that says: "would this be in
   * the default report with the exploit-focused defaults?"
   */
  private isExploitableFinding(finding: Finding): boolean {
    // Default semantics: CRITICAL always counts; non-heuristic HIGH counts.
    if (finding.severity === 'CRITICAL') return true;
    if (finding.severity === 'HIGH' && finding.ruleId && !isHeuristic(finding.ruleId)) {
      return true;
    }
    return false;
  }

  private getReportFindings(): Finding[] {
    const enriched = this.findings.map((finding) => this.enrichForReport(finding));
    const suppressedAccumulator: Finding[] = [];
    const includeHeuristics = this.analysisOptions.includeHeuristics === true;
    const minSeverity: Severity = this.analysisOptions.minSeverity
      ?? (includeHeuristics ? 'LOW' : 'HIGH');
    const disabledRules = new Set(
      (this.analysisOptions.disabledRules ?? []).map((id) => id.toUpperCase())
    );

    const visible: Finding[] = [];

    for (const finding of enriched) {
      // 1. Rule-id disable
      if (finding.ruleId && disabledRules.has(finding.ruleId.toUpperCase())) {
        continue;
      }

      // 2. Heuristic gate (default report drops heuristic rules; legacy "exploitable" subset preserved)
      const heuristicFlag = finding.ruleId ? isHeuristic(finding.ruleId) : false;
      if (heuristicFlag && !includeHeuristics) {
        continue;
      }

      // 3. Severity threshold
      if (!severityAtLeast(finding.severity, minSeverity)) {
        continue;
      }

      // 4. Inline suppression
      const inlineMap = this.inlineSuppressionByFile.get(this.toAbsoluteFile(finding.file));
      if (inlineMap) {
        const result = isLineSuppressed(inlineMap, finding.line, finding.ruleId);
        if (result.suppressed) {
          suppressedAccumulator.push({
            ...finding,
            suppressed: { source: 'inline', reason: result.reason },
          });
          continue;
        }
      }

      // 5. Baseline suppression
      if (this.baseline) {
        const entry = this.baseline.match(finding);
        if (entry) {
          suppressedAccumulator.push({
            ...finding,
            suppressed: { source: 'baseline', reason: entry.reason },
          });
          continue;
        }
      }

      visible.push(finding);
    }

    this.suppressedFindings = suppressedAccumulator;

    // Deterministic sort: severity desc, then file asc, then line asc, then ruleId asc.
    visible.sort((a, b) => {
      const severityDiff = severityRank(b.severity) - severityRank(a.severity);
      if (severityDiff !== 0) return severityDiff;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      if (a.line !== b.line) return a.line - b.line;
      const aRule = a.ruleId ?? '';
      const bRule = b.ruleId ?? '';
      return aRule < bRule ? -1 : aRule > bRule ? 1 : 0;
    });

    return visible;
  }

  /**
   * Backfill rule-registry metadata + fingerprint, and normalize file path for display.
   */
  private enrichForReport(finding: Finding): Finding {
    const ruleId = finding.ruleId;
    const rule = ruleId ? getRule(ruleId) : undefined;

    const enriched: Finding = {
      ...finding,
      file: this.toDisplayPath(finding.file),
      cwe: finding.cwe ?? rule?.cwe,
      owasp: finding.owasp ?? rule?.owasp,
    };

    enriched.fingerprint = enriched.fingerprint ?? computeFingerprint(enriched);
    return enriched;
  }

  private getDirectoryIgnorePatterns(targetPath: string): string[] {
    const excludedDirectories = ['dist', 'coverage', 'tests', '__tests__', 'pocs'];
    const targetParts = path.resolve(targetPath).split(path.sep);

    return excludedDirectories
      .filter((directoryName) => !targetParts.includes(directoryName))
      .map((directoryName) => `**/${directoryName}/**`);
  }

  private addRuntimeIssue(issue: RuntimeIssue): void {
    this.runtimeIssues.push({
      ...issue,
      file: issue.file ? this.toDisplayPath(issue.file) : undefined,
      outputPath: issue.outputPath ? this.toDisplayPath(issue.outputPath) : undefined,
    });
  }

  private matchesPocToFinding(poc: ProofOfConcept, findings: Finding[]): boolean {
    const pocLocation = this.extractPocLocation(poc);

    if (pocLocation) {
      return findings.some(
        (finding) =>
          this.toDisplayPath(finding.file) === pocLocation.file &&
          finding.line === pocLocation.line &&
          this.hasMeaningfulTitleMatch(poc.title, finding.title)
      );
    }

    if (poc.findingId) {
      return findings.some((finding) => `${finding.category}-${finding.line}` === poc.findingId);
    }

    return findings.some((finding) => poc.title.includes(finding.title));
  }

  private extractPocLocation(poc: ProofOfConcept): { file: string; line: number } | null {
    for (const step of poc.steps) {
      if (step.filePath && typeof step.lineNumber === 'number') {
        return {
          file: this.toDisplayPath(step.filePath),
          line: step.lineNumber,
        };
      }
    }

    for (const component of poc.codeFlow.components) {
      if (!component.location) {
        continue;
      }

      const match = component.location.match(/^(.*):(\d+)$/);
      if (match) {
        return {
          file: this.toDisplayPath(match[1]),
          line: Number(match[2]),
        };
      }
    }

    return null;
  }

  private hasMeaningfulTitleMatch(left: string, right: string): boolean {
    if (left === right) {
      return true;
    }

    const loweredLeft = left.toLowerCase();
    const loweredRight = right.toLowerCase();
    if (loweredLeft.includes('hardcoded') && loweredRight.includes('hardcoded')) {
      return true;
    }

    const normalize = (value: string) =>
      new Set(
        value
          .toLowerCase()
          .replace(/[^a-z0-9\s]/g, ' ')
          .split(/\s+/)
          .filter((token) => token.length > 3)
      );

    const leftTokens = normalize(left);
    const rightTokens = normalize(right);
    let overlap = 0;

    leftTokens.forEach((token) => {
      if (rightTokens.has(token)) {
        overlap++;
      }
    });

    return overlap >= 2;
  }

  private toDisplayPath(filePath: string): string {
    return normalizePath(filePath);
  }

  private toAbsoluteFile(displayOrAbsolute: string): string {
    if (path.isAbsolute(displayOrAbsolute)) {
      return displayOrAbsolute;
    }
    return path.resolve(process.cwd(), displayOrAbsolute);
  }

}
