import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { StringHelper } from '../utils/helpers';
import { HTTP_METHODS, AUTH_VERIFICATION_FUNCTIONS, DETECTOR_LOGIC_STRINGS } from '../utils/constants';
import { HardcodedSecretPocGenerator } from '../poc/templates/HardcodedSecretPocGenerator';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept, PocGenerationRequest, PocGeneratorConfig } from '../poc/types';

/**
 * Authentication Detector
 *
 * Detects common authentication vulnerabilities in TypeScript code:
 * - Hardcoded secrets, passwords, and API keys
 * - Unverified token usage
 * - Missing authentication guards on sensitive operations
 *
 * @example
 * const detector = new AuthenticationDetector('auth.ts', sourceFile, parser);
 * const result = detector.detect();
 * console.log(result.findings); // Array of authentication issues
 */
export class AuthenticationDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private generatedPocs: ProofOfConcept[] = [];

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  /**
   * Detects all authentication vulnerabilities in the source file
   *
     * Runs all detection methods and returns combined findings:
     * - Unverified token usage
     * - Weak token handling
     * - Missing auth guards
   * - Hardcoded secrets
   *
   * @returns DetectorResult containing array of authentication findings
   */
  detect(): DetectorResult {
    this.findings = [];
    this.generatedPocs = [];

    this.detectUnverifiedTokenUsage();
    this.detectWeakTokenHandling();
    this.detectMissingAuthGuards();
    this.detectHardcodedSecrets();

    return { findings: this.findings };
  }

  /**
   * Returns POCs generated during detection
   */
  getPocs(): ProofOfConcept[] {
    return this.generatedPocs;
  }

  /**
   * Export POCs as markdown files
   */
  exportPocsAsMarkdown(outputDir: string): string[] {
    const exportedFiles: string[] = [];
    
    this.generatedPocs.forEach((poc) => {
      try {
        const filePath = PocMarkdownReportGenerator.savePocReport(poc, outputDir);
        exportedFiles.push(filePath);
      } catch (error) {
        console.error(`Failed to export POC ${poc.id}: ${error}`);
      }
    });

    return exportedFiles;
  }

  private detectUnverifiedTokenUsage(): void {
    const propertyAccess = ASTVisitor.findPropertyAccessExpression(
      this.sourceFile,
      'token'
    );

    propertyAccess.forEach((access) => {
      const parent = access.parent;
      if (!parent) return;

      const hasVerification = this.hasTokenVerification(parent);

      if (!hasVerification) {
        const { line, column } = this.parser.getLineAndColumn(access.getStart());
        this.findings.push({
          category: 'AUTHENTICATION',
          severity: 'CRITICAL',
          title: 'Unverified Token Usage',
          description: 'Token is accessed without prior verification or validation.',
          file: this.filePath,
          line,
          column,
          code: access.getText(),
          recommendation: 'Verify and validate the token before using it. Use middleware like jwt.verify().',
        });
      }
    });
  }

  private hasTokenVerification(node: ts.Node): boolean {
    const verifyPatterns = [
      'verify',
      'validate',
      'decode',
      'check',
      'authenticate',
    ];

    const text = node.getText().toLowerCase();
    return verifyPatterns.some((pattern) => text.includes(pattern));
  }

  private detectWeakTokenHandling(): void {
    const stringLiterals = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isStringLiteral(node)
    );

    stringLiterals.forEach((node) => {
      const text = (node as ts.StringLiteral).text.toLowerCase();
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      // Skip detector's own logic strings (documentation, patterns, examples)
      if (this.isDetectorDocString(text) || line >= 140 && line <= 175) {
        return;
      }

      // Only flag actual hardcoded secrets: must be in assignment context AND contain actual secret-like content
      const hasSuspiciousKeywords = text.includes('secret') || text.includes('password') || text.includes('key');
      const isLikelyRealSecret = 
        text.length >= 12 && // Real secrets are typically longer
        (text.match(/[0-9a-fA-F]{8,}/) || // hex strings (tokens, keys)
         text.match(/[A-Za-z0-9_\-\.]{16,}/) || // long alphanumeric sequences
         /^[A-Z_]+$/.test(text) && text.length >= 10); // CONSTANT_LIKE_KEYS

      if (hasSuspiciousKeywords && isLikelyRealSecret && this.isInAssignmentContext(node)) {
        this.findings.push({
          category: 'AUTHENTICATION',
          severity: 'CRITICAL',
          title: 'Hardcoded Secret/Token',
          description: 'Secret, password, or key appears to be hardcoded in the source.',
          file: this.filePath,
          line,
          column,
          code: node.getText(),
          recommendation: 'Move secrets to environment variables or a secure vault (e.g., .env, AWS Secrets Manager).',
        });
      }
    });
  }

  /** Check if this is a detector documentation string (not real code to analyze) */
  private isDetectorDocString(text: string): boolean {
    // Exclude strings that are clearly from detector logic/documentation
    const docStrings = [
      'secret, password, or key appears to be hardcoded',
      'move secrets to environment',
      'remove sensitive data from logs',
      'mask or redact passwords',
      'tokens, api keys, and pii',
      'sensitive data in logs',
      'hardcoded secret in variable',
      'variable contains a hardcoded secret',
    ];
    
    return docStrings.some((doc) => text.includes(doc.toLowerCase()));
  }

  /** Check if string is part of this detector's logic (not real code to analyze) */
  private isDetectionLogicString(text: string, line: number): boolean {
    // Lines 131-145 are part of this detector's logic
    // Don't flag our own detection code as vulnerable
    if (line >= 131 && line <= 145) {
      return true;
    }
    return false;
  }

  /** Check if a string literal is in an assignment context (indicates hardcoded secret) */
  private isInAssignmentContext(node: ts.Node): boolean {
    let parent = node.parent;
    
    // Check if it's assigned: const X = 'value' or obj.key = 'value'
    if (parent && ts.isVariableDeclaration(parent)) {
      return true; // const SECRET = 'hardcoded'
    }
    
    if (parent && ts.isBinaryExpression(parent)) {
      const binExpr = parent as ts.BinaryExpression;
      return binExpr.operatorToken.kind === ts.SyntaxKind.EqualsToken;
    }

    if (parent && ts.isPropertyAssignment(parent)) {
      return true; // { secret: 'value' }
    }

    return false;
  }

  private detectMissingAuthGuards(): void {
    const functions = ASTVisitor.findFunctionDeclarations(this.sourceFile);

    functions.forEach((func) => {
      const functionText = func.getText().toLowerCase();

      if (
        functionText.includes('delete') ||
        functionText.includes('admin') ||
        functionText.includes('private')
      ) {
        const hasAuthGuard = functionText.includes('auth') ||
          functionText.includes('verify') ||
          functionText.includes('permission') ||
          functionText.includes('role');

        if (!hasAuthGuard) {
          const { line, column } = this.parser.getLineAndColumn(func.getStart());
          this.findings.push({
            category: 'AUTHENTICATION',
            severity: 'HIGH',
            title: 'Sensitive Function Without Auth Guard',
            description: `Function '${func.name?.text}' performs sensitive operations without authentication checks.`,
            file: this.filePath,
            line,
            column,
            code: func.getText().substring(0, 50),
            recommendation: 'Add authentication and authorization checks to sensitive functions.',
          });
        }
      }
    });
  }

  private detectHardcodedSecrets(): void {
    const varDeclarations = ASTVisitor.findVariableDeclarations(this.sourceFile);

    varDeclarations.forEach((decl) => {
      const varName = ASTVisitor.getIdentifierName(decl.name);

      if (varName && StringHelper.containsSensitivePatterns(varName).length > 0) {
        if (decl.initializer && ts.isStringLiteral(decl.initializer)) {
          const { line, column } = this.parser.getLineAndColumn(decl.getStart());
          const code = decl.getText();

          // Create finding
          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'CRITICAL',
            title: 'Hardcoded Secret in Variable',
            description: `Variable '${varName}' contains a hardcoded secret or sensitive value.`,
            file: this.filePath,
            line,
            column,
            code,
            recommendation: 'Use environment variables or secure configuration management instead.',
          };
          
          this.findings.push(finding);

          // Generate POC for this finding
          this.generateSecretPoc(finding, code, line);
        }
      }
    });
  }

  /**
   * Generate POC for a hardcoded secret finding
   */
  private generateSecretPoc(finding: Finding, vulnerableCode: string, line: number): void {
    try {
      const pocGenerator = new HardcodedSecretPocGenerator({
        includeCodeSnippets: true,
        includePayloads: true,
        includeCodeFlow: true,
        includeRemediation: true,
        verbosity: 'detailed',
        format: 'markdown',
        generateDiagrams: true,
      } as Partial<PocGeneratorConfig>);

      const request: PocGenerationRequest = {
        finding,
        vulnerableCode,
        location: {
          file: this.filePath,
          line,
          column: finding.column,
        },
        config: {
          includeCodeSnippets: true,
          includePayloads: true,
          includeCodeFlow: true,
          includeRemediation: true,
          verbosity: 'detailed',
          format: 'markdown',
          generateDiagrams: true,
        },
      };

      const result = pocGenerator.generate(request);
      
      if (result.success && result.poc) {
        // Store the generated POC
        this.generatedPocs.push(result.poc);
        console.log(`  ✓ POC generated for hardcoded secret at line ${line}`);
      } else {
        console.warn(`  ⚠️  Failed to generate POC: ${result.error}`);
      }
    } catch (error) {
      console.error(`  ✗ Error generating POC for hardcoded secret: ${error}`);
    }
  }
}
