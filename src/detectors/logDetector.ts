import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { StringHelper } from '../utils/helpers';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept } from '../poc/types';

/**
 * A real logger call. The previous substring-based isLoggerCall matched any function
 * whose name contained "log" — including `authService.loginUserWithEmailAndPassword(...)`
 * and `dialog.open(...)`. Real loggers have a recognised receiver: `console`, `logger`,
 * `winston`, `pino`, `bunyan`, `log` (a bare logger object).
 */
function isExplicitLoggerCall(node: ts.CallExpression): boolean {
  const expr = node.expression;
  if (!ts.isPropertyAccessExpression(expr)) return false;
  // Method must be a recognised log level.
  if (!/^(log|debug|trace|info|notice|warn|warning|error|fatal|silly|verbose)$/i.test(expr.name.text)) {
    return false;
  }
  // Receiver must be an explicit logger object. We support chained loggers like
  // `this.logger.info(...)` and `logger.child({}).warn(...)` by walking the chain.
  let receiver: ts.Node = expr.expression;
  while (true) {
    if (ts.isIdentifier(receiver)) {
      return /^(console|logger|log|winston|pino|bunyan|debug|child|parent)$/i.test(receiver.text);
    }
    if (ts.isPropertyAccessExpression(receiver)) {
      // this.logger | self.log
      if (/^(logger|log|winston|pino|bunyan)$/i.test(receiver.name.text)) return true;
      receiver = receiver.expression;
      continue;
    }
    if (ts.isCallExpression(receiver)) {
      receiver = receiver.expression;
      continue;
    }
    return false;
  }
}

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
      return ts.isCallExpression(node) && isExplicitLoggerCall(node);
    });

    callExpressions.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      callExpr.arguments.forEach((arg) => {
        // Skip plain string-literal arguments: a literal like `'password reset sent'`
        // contains the word `password` but doesn't actually log a secret. Real leaks
        // come from template literals, identifiers, object/property accesses.
        if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
          return;
        }
        const argText = arg.getText();
        const sensitivePatterns = StringHelper.containsSensitivePatterns(argText);

        if (sensitivePatterns.length > 0) {
          const { line, column } = this.parser!.getLineAndColumn(arg.getStart());

          const finding: Finding = {
            ruleId: 'BCR-LOG-001',
            category: 'LOGGING',
            severity: 'HIGH',
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
      // Find the enclosing CallExpression; must be an explicit logger call.
      let parent: ts.Node | undefined = node.parent;
      let enclosingCall: ts.CallExpression | undefined;
      while (parent) {
        if (ts.isCallExpression(parent)) { enclosingCall = parent; break; }
        parent = parent.parent;
      }
      if (!enclosingCall || !isExplicitLoggerCall(enclosingCall)) return;

      const exprText = node.getText();
      // Tightened: require a real request-data source. Previously `user.` matched
      // `events.user.signIn`, `req.` matched `request.id`, etc.
      if (/(req|request)\.(body|params|query|headers|cookies)|ctx\.request\.(body|params|query|headers)/i.test(exprText)) {
        const { line, column } = this.parser!.getLineAndColumn(node.getStart());
        this.findings.push({
          ruleId: 'BCR-LOG-002',
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
    });
  }

}
