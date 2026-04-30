import * as ts from 'typescript';
import * as path from 'path';
import * as fs from 'fs';
import {
  AnalysisReport,
  DetectorResult,
  Finding,
  IssueCategory,
  RuntimeIssue,
  RuntimeIssueType,
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
import { FileHelper } from './utils/helpers';
import { ProofOfConcept } from './poc/types';
import { PocMarkdownReportGenerator } from './poc/PocMarkdownReportGenerator';
import { Logger } from './utils/logger';

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

interface AnalysisOptions {
  includeHeuristics?: boolean;
}

/**
 * Backend Code Review Analyzer
 *
 * Orchestrates detector execution over TypeScript files and aggregates findings/POCs.
 */
export class BackendCodeReviewAnalyzer {
  private findings: Finding[] = [];
  private filesAnalyzed = 0;
  private generatedPocs: ProofOfConcept[] = [];
  private runtimeIssues: RuntimeIssue[] = [];
  private analysisOptions: AnalysisOptions = {};
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
  ];

  analyze(targetPath: string, options: AnalysisOptions = {}): AnalysisReport {
    this.resetState();
    this.analysisOptions = options;

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
      Logger.error('Fatal error during analysis', { error: errorMessage });
      return this.generateReport();
    }
  }

  getPocs(): ProofOfConcept[] {
    const reportFindings = this.getReportFindings();
    return this.generatedPocs.filter((poc) => this.matchesPocToFinding(poc, reportFindings));
  }

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
        Logger.error(`Failed to export POC ${poc.id}`, { error: errorMessage });
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

  private resetState(): void {
    this.findings = [];
    this.generatedPocs = [];
    this.filesAnalyzed = 0;
    this.runtimeIssues = [];
  }

  private getTargetFiles(targetPath: string): string[] {
    if (FileHelper.isFile(targetPath)) {
      return [targetPath];
    }

    if (FileHelper.isDirectory(targetPath)) {
      return FileHelper.getAllTypeScriptFiles(targetPath);
    }

    this.addRuntimeIssue({
      type: 'INVALID_TARGET',
      severity: 'ERROR',
      message: `Path not found: ${targetPath}`,
      file: targetPath,
    });
    Logger.error(`Path not found: ${targetPath}`);
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
      Logger.warn(`Skipping ${filePath} - failed to parse`, {
        error: parser.getLastError() || 'syntax error',
      });
      return;
    }

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
        Logger.warn(`Detector ${detectorFactory.name} failed in ${filePath}`, {
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

  private generateReport(): AnalysisReport {
    const reportFindings = this.getReportFindings();
    const findingsByCategory: Record<IssueCategory, number> = {
      AUTHENTICATION: 0,
      VALIDATION: 0,
      LOGGING: 0,
      MASS_ASSIGNMENT: 0,
      ACCESS_CONTROL: 0,
      RATE_LIMITING: 0,
      BUSINESS_LOGIC: 0,
      API_KEY_EXPOSURE: 0,
      CRYPTO_WEAKNESS: 0,
      DATA_EXPOSURE: 0,
      CACHE_POISONING: 0,
      MESSAGE_QUEUE: 0,
      EVENT_STREAM: 0,
    };
    const runtimeIssuesByType = this.createRuntimeIssueCountMap();

    const findingsBySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    reportFindings.forEach((finding) => {
      findingsByCategory[finding.category]++;
      findingsBySeverity[finding.severity]++;
    });
    this.runtimeIssues.forEach((issue) => {
      runtimeIssuesByType[issue.type]++;
    });

    const severityOrder: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    };

    const sortedFindings = [...reportFindings].sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );

    return {
      timestamp: new Date().toISOString(),
      filesAnalyzed: this.filesAnalyzed,
      totalFindings: reportFindings.length,
      findingsByCategory,
      findingsBySeverity,
      findings: sortedFindings,
      runtimeIssues: [...this.runtimeIssues],
      runtimeIssuesByType,
      hasRuntimeErrors: this.runtimeIssues.some((issue) => issue.severity === 'ERROR'),
    };
  }

  private isExploitableFinding(finding: Finding): boolean {
    if (finding.severity === 'CRITICAL') {
      return true;
    }

    const combinedText = `${finding.title} ${finding.description}`;
    const excludedTitlePatterns = [
      /global-only rate limiting without per-user limits/i,
      /missing key id \(kid\) validation/i,
      /unsafe object\.assign with untrusted data/i,
      /unsafe object spread with untrusted data/i,
      /weak hashing:/i,
      /missing rate limiting on sensitive endpoint/i,
      /missing field whitelisting/i,
    ];

    if (excludedTitlePatterns.some((pattern) => pattern.test(combinedText))) {
      return false;
    }

    const patternsByCategory: Partial<Record<IssueCategory, Record<'HIGH' | 'MEDIUM' | 'LOW', RegExp[]>>> = {
      AUTHENTICATION: {
        HIGH: [
          /jwt|token|algorithm confusion|key confusion|weak jwt secret|expiration check disabled|cached jwt/i,
          /sensitive function without auth guard/i,
          /hardcoded secret/i,
        ],
        MEDIUM: [],
        LOW: [],
      },
      VALIDATION: {
        HIGH: [
          /unvalidated input reaches/i,
          /unsafe json\.parse/i,
          /code injection via eval/i,
          /prototype pollution/i,
          /potential gadget chain usage/i,
        ],
        MEDIUM: [],
        LOW: [],
      },
      LOGGING: {
        HIGH: [/sensitive data in logs|log injection risk/i],
        MEDIUM: [],
        LOW: [],
      },
      MASS_ASSIGNMENT: {
        HIGH: [
          /direct object\.assign with user input/i,
          /unvalidated field assignment/i,
          /prototype pollution vulnerability/i,
          /constructor\/prototype property assignment/i,
        ],
        MEDIUM: [],
        LOW: [],
      },
      ACCESS_CONTROL: {
        HIGH: [/authorization check on sensitive endpoint|ownership verification|privilege escalation|idor|bola/i],
        MEDIUM: [],
        LOW: [],
      },
      RATE_LIMITING: {
        HIGH: [
          /rate limit bypass via header manipulation/i,
          /weak rate limiting on sensitive endpoint/i,
          /distributed rate limit bypass via load balancer/i,
        ],
        MEDIUM: [],
        LOW: [],
      },
      BUSINESS_LOGIC: {
        HIGH: [/race condition|idempotency|time-of-check|client-controlled price|inventory over-selling/i],
        MEDIUM: [],
        LOW: [],
      },
      API_KEY_EXPOSURE: {
        HIGH: [/hardcoded|key in logs|key in comment|key in error message|database credentials/i],
        MEDIUM: [],
        LOW: [],
      },
      CRYPTO_WEAKNESS: {
        HIGH: [/predictable token with math\.random|hardcoded cryptographic key/i],
        MEDIUM: [],
        LOW: [],
      },
      DATA_EXPOSURE: {
        HIGH: [/sensitive field .* exposed in response|unfiltered sensitive data in api response/i],
        MEDIUM: [],
        LOW: [],
      },
      CACHE_POISONING: {
        HIGH: [/cache poisoning/i],
        MEDIUM: [],
        LOW: [],
      },
      MESSAGE_QUEUE: {
        HIGH: [/queue consumer deserialization|unsigned queue publish|integrity not verified before ack/i],
        MEDIUM: [],
        LOW: [],
      },
      EVENT_STREAM: {
        HIGH: [/event handler injection|event name enables handler abuse|tenant scoping/i],
        MEDIUM: [],
        LOW: [],
      },
    };

    const categoryPatterns = patternsByCategory[finding.category];
    if (!categoryPatterns) {
      return false;
    }

    const severityPatterns = categoryPatterns[finding.severity as 'HIGH' | 'MEDIUM' | 'LOW'] || [];
    return severityPatterns.some((pattern) => pattern.test(combinedText));
  }

  private getReportFindings(): Finding[] {
    const visibleFindings = this.analysisOptions.includeHeuristics
      ? [...this.findings]
      : this.getExploitableFindings(this.findings);

    return visibleFindings.map((finding) => ({
      ...finding,
      file: this.toDisplayPath(finding.file),
    }));
  }

  private createRuntimeIssueCountMap(): Record<RuntimeIssueType, number> {
    return {
      INVALID_TARGET: 0,
      PARSE_FAILURE: 0,
      DETECTOR_FAILURE: 0,
      POC_EXPORT_FAILURE: 0,
      REPORT_WRITE_FAILURE: 0,
      FATAL_ANALYSIS_FAILURE: 0,
    };
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
    const relativePath = path.isAbsolute(filePath)
      ? path.relative(process.cwd(), filePath)
      : filePath;
    return relativePath.split(path.sep).join('/');
  }
}
