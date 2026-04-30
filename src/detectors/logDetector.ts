import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { StringHelper } from '../utils/helpers';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept } from '../poc/types';

export class LogReviewDetector {
  private findings: Finding[] = [];
  private filePath: string = '';
  private sourceFile: ts.SourceFile | null = null;
  private parser: ASTParser | null = null;
  private pocs: ProofOfConcept[] = [];

  constructor(filePath?: string, sourceFile?: ts.SourceFile, parser?: ASTParser) {
    if (filePath) this.filePath = filePath;
    if (sourceFile) this.sourceFile = sourceFile;
    if (parser) this.parser = parser;
  }

  detect(): DetectorResult {
    this.findings = [];
    this.pocs = [];

    // Skip detection if source file or parser not set
    if (!this.sourceFile || !this.parser) {
      return { findings: this.findings };
    }

    this.detectSensitiveDataLogging();
    this.detectLogInjectionRisks();

    return { findings: this.findings };
  }

  /**
   * Get all POCs generated during detection
   */
  getPocs(): ProofOfConcept[] {
    return this.pocs;
  }

  /**
   * Export POCs as markdown files to directory
   */
  exportPocsAsMarkdown(outputDir: string): string[] {
    const exportedFiles: string[] = [];

    this.pocs.forEach((poc) => {
      const filePath = PocMarkdownReportGenerator.savePocReport(poc, outputDir);
      exportedFiles.push(filePath);
    });

    return exportedFiles;
  }

  private detectSensitiveDataLogging(): void {
    const callExpressions = ASTVisitor.findNodes(this.sourceFile!, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        return !!(name && StringHelper.isLoggerCall(name));
      }
      return false;
    });

    callExpressions.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      callExpr.arguments.forEach((arg) => {
        const argText = arg.getText();
        const sensitivePatterns = StringHelper.containsSensitivePatterns(argText);

        if (sensitivePatterns.length > 0) {
          const { line, column } = this.parser!.getLineAndColumn(arg.getStart());
          
          const finding: Finding = {
            category: 'LOGGING',
            severity: 'CRITICAL',
            title: 'Sensitive Data in Logs',
            description: `Log statement contains sensitive data: ${sensitivePatterns.join(', ')}`,
            file: this.filePath,
            line,
            column,
            code: argText.substring(0, 50),
            recommendation: 'Remove sensitive data from logs. Mask or redact passwords, tokens, API keys, and PII.',
          };

          this.findings.push(finding);
        }
      });
    });
  }

  private detectLogInjectionRisks(): void {
    const templateLiterals = ASTVisitor.findNodes(
      this.sourceFile!,
      (node) => ts.isTemplateExpression(node)
    );

    templateLiterals.forEach((node) => {
      const parent = node.parent;
      if (!parent) return;

      const parentText = parent.getText().toLowerCase();
      if (parentText.includes('log') || parentText.includes('console')) {
        const exprText = node.getText();

        if (exprText.includes('req.') || exprText.includes('user.')) {
          const { line, column } = this.parser!.getLineAndColumn(node.getStart());
          this.findings.push({
            category: 'LOGGING',
            severity: 'HIGH',
            title: 'Log Injection Risk',
            description: 'User input is directly interpolated into log messages.',
            file: this.filePath,
            line,
            column,
            code: exprText.substring(0, 50),
            recommendation: 'Log user input separately and use structured logging to prevent injection attacks.',
          });
        }
      }
    });
  }

}
