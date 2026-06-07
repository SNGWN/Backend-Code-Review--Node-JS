import * as fs from 'fs';
import { AnalysisReport, Confidence, Finding, IssueCategory, RuntimeIssue, RuntimeIssueType, Severity } from './types';
import { Logger } from './utils/logger';

export class JSONReporter {
  static generateReport(
    findings: Finding[],
    filesAnalyzed: number,
    runtimeIssues: RuntimeIssue[] = []
  ): AnalysisReport {
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
      SSRF: 0,
      PATH_TRAVERSAL: 0,
      OPEN_REDIRECT: 0,
      MISCONFIGURATION: 0,
      LOG_PCI: 0,
      LOG_PII: 0,
      LOG_SECRET: 0,
      LOG_OPS: 0,
    };
    const runtimeIssuesByType: Record<RuntimeIssueType, number> = {
      INVALID_TARGET: 0,
      PARSE_FAILURE: 0,
      DETECTOR_FAILURE: 0,
      POC_EXPORT_FAILURE: 0,
      REPORT_WRITE_FAILURE: 0,
      FATAL_ANALYSIS_FAILURE: 0,
    };

    const findingsBySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    const findingsByConfidence: Record<Confidence, number> = {
      CONFIRMED: 0,
      FIRM: 0,
      TENTATIVE: 0,
    };
    const findingsByRule: Record<string, number> = {};
    findings.forEach((finding) => {
      findingsByCategory[finding.category]++;
      findingsBySeverity[finding.severity]++;
      if (finding.confidence) findingsByConfidence[finding.confidence]++;
      const id = finding.ruleId ?? `LEGACY:${finding.category}`;
      findingsByRule[id] = (findingsByRule[id] ?? 0) + 1;
    });
    runtimeIssues.forEach((issue) => {
      runtimeIssuesByType[issue.type]++;
    });

    return {
      timestamp: new Date().toISOString(),
      filesAnalyzed,
      totalFindings: findings.length,
      findingsByCategory,
      findingsBySeverity,
      findingsByConfidence,
      findingsByRule,
      // Trust the caller's ordering — `analyzer.getReportFindings()` already sorts
      // deterministically (severity desc, file asc, line asc, ruleId asc) and we
      // must not clobber that. Previously this re-sorted ascending AND mutated the
      // shared array, breaking analyzer determinism and aliasing the input.
      findings: [...findings],
      runtimeIssues,
      runtimeIssuesByType,
      hasRuntimeErrors: runtimeIssues.some((issue) => issue.severity === 'ERROR'),
    };
  }

  static writeReport(report: AnalysisReport, outputPath: string): void {
    try {
      fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
      Logger.success(`Report saved to ${outputPath}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error(`Error writing report to ${outputPath}`, { error: errorMessage });
      throw error;
    }
  }

  static writeTextReport(report: AnalysisReport, outputPath: string): void {
    try {
      fs.writeFileSync(outputPath, this.generateTextReport(report), 'utf-8');
      Logger.success(`Text report saved to ${outputPath}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error(`Error writing text report to ${outputPath}`, { error: errorMessage });
      throw error;
    }
  }

  static printSummary(report: AnalysisReport): void {
    if (Logger.getConfig().format === 'json') {
      Logger.info('analysis-summary', {
        filesAnalyzed: report.filesAnalyzed,
        totalFindings: report.totalFindings,
        findingsByCategory: report.findingsByCategory,
        findingsBySeverity: report.findingsBySeverity,
        runtimeIssues: report.runtimeIssuesByType,
      });
      return;
    }

    Logger.info('\n╔════════════════════════════════════════════╗');
    Logger.info('║       Backend Code Review Analysis         ║');
    Logger.info('╚════════════════════════════════════════════╝\n');

    Logger.info(`Files analyzed:      ${report.filesAnalyzed}`);
    Logger.info(`Total findings:      ${report.totalFindings}\n`);

    Logger.info('Findings by Category:');
    Object.entries(report.findingsByCategory).forEach(([category, count]) => {
      Logger.info(`  • ${this.formatCategoryLabel(category)}: ${count}`);
    });
    Logger.info('');

    Logger.info('Findings by Severity:');
    Logger.info(`  • CRITICAL:         ${report.findingsBySeverity.CRITICAL}`);
    Logger.info(`  • HIGH:             ${report.findingsBySeverity.HIGH}`);
    Logger.info(`  • MEDIUM:           ${report.findingsBySeverity.MEDIUM}`);
    Logger.info(`  • LOW:              ${report.findingsBySeverity.LOW}`);
    Logger.info(`  • INFO:             ${report.findingsBySeverity.INFO}\n`);

    if (report.findingsByConfidence) {
      Logger.info('Findings by Confidence:');
      Logger.info(`  • CONFIRMED:        ${report.findingsByConfidence.CONFIRMED}`);
      Logger.info(`  • FIRM:             ${report.findingsByConfidence.FIRM}`);
      Logger.info(`  • TENTATIVE (review): ${report.findingsByConfidence.TENTATIVE}\n`);
    }

    if (report.runtimeIssues.length > 0) {
      Logger.warn(`Runtime issues: ${report.runtimeIssues.length}`);
    }

    if (report.totalFindings > 0) {
      Logger.info('Top Issues:');
      const topIssues = report.findings.slice(0, 5);
      topIssues.forEach((finding, index) => {
        Logger.info(`\n${index + 1}. [${finding.severity}] ${finding.title}`);
        Logger.info(`   File: ${finding.file}:${finding.line}:${finding.column}`);
        Logger.info(`   ${finding.description}`);
      });

      if (report.totalFindings > 5) {
        Logger.info(`\n... and ${report.totalFindings - 5} more findings`);
      }
    }

    Logger.info('\n');
  }

  private static formatCategoryLabel(category: string): string {
    return category
      .toLowerCase()
      .split('_')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ');
  }

  private static generateTextReport(report: AnalysisReport): string {
    const lines: string[] = [];
    lines.push('Backend Code Review Analysis');
    lines.push(`Timestamp: ${report.timestamp}`);
    lines.push(`Files analyzed: ${report.filesAnalyzed}`);
    lines.push(`Total findings: ${report.totalFindings}`);
    lines.push('');
    lines.push('Findings by Category:');
    Object.entries(report.findingsByCategory).forEach(([category, count]) => {
      lines.push(`- ${this.formatCategoryLabel(category)}: ${count}`);
    });
    lines.push('');
    lines.push('Findings by Severity:');
    Object.entries(report.findingsBySeverity).forEach(([severity, count]) => {
      lines.push(`- ${severity}: ${count}`);
    });
    lines.push('');
    if (report.runtimeIssues.length > 0) {
      lines.push('Runtime Issues:');
      report.runtimeIssues.forEach((issue, index) => {
        lines.push(
          `${index + 1}. [${issue.severity}] ${issue.type} - ${issue.message}${issue.file ? ` (${issue.file})` : ''}`
        );
      });
      lines.push('');
    }
    lines.push('Findings:');
    report.findings.forEach((finding, index) => {
      lines.push(
        `${index + 1}. [${finding.severity}] ${finding.title} (${finding.file}:${finding.line}:${finding.column})`
      );
      lines.push(`   Category: ${this.formatCategoryLabel(finding.category)}`);
      if (finding.confidence) lines.push(`   Confidence: ${finding.confidence}`);
      lines.push(`   Description: ${finding.description}`);
      if (finding.verify) lines.push(`   To verify: ${finding.verify}`);
      lines.push(`   Recommendation: ${finding.recommendation}`);
    });

    return lines.join('\n');
  }
}
