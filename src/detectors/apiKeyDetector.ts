import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept } from '../poc/types';

/**
 * API Key/Secrets Exposure Detector
 *
 * Detects various forms of API key and sensitive credential exposure:
 * - Hardcoded API keys from major services (AWS, Stripe, Twilio, etc.)
 * - Keys in environment variables without protection
 * - Keys in configuration files
 * - Keys in function parameters and defaults
 * - Keys in test files and fixtures
 * - Keys in comments, error messages, and logs
 *
 * @example
 * const detector = new ApiKeyDetector('config.ts', sourceFile, parser);
 * const result = detector.detect();
 */
export class ApiKeyDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private generatedPocs: ProofOfConcept[] = [];

  // API Key patterns for various services
  private readonly API_KEY_PATTERNS = {
    // AWS patterns
    aws_access_key: /AKIA[0-9A-Z]{16}/,
    aws_secret_key: /aws_secret_access_key|aws_secret|AKIA|wJal[rRtT]|aws_access_key_id/i,
    
    // Stripe patterns
    stripe_live_key: /sk_live_[0-9a-zA-Z]{24}/,
    stripe_test_key: /sk_test_[0-9a-zA-Z]{24}/,
    stripe_public_key: /pk_live_[0-9a-zA-Z]{24}|pk_test_[0-9a-zA-Z]{24}/,
    
    // Twilio patterns
    twilio_key: /AC[a-zA-Z0-9]{32}/,
    twilio_auth: /twilio_auth|twilio_sid|twilio_token/i,
    
    // SendGrid patterns
    sendgrid_key: /SG\.[a-zA-Z0-9_-]{20,}/,
    
    // GitHub tokens
    github_token: /ghp_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}/,
    
    // Firebase
    firebase_key: /AIza[0-9A-Za-z_-]{35}/,
    
    // Generic API key patterns
    generic_api_key: /api[_-]?key|apikey|api_key|API_KEY|api-key/i,
    generic_secret: /secret|SECRET|SECRET_KEY|secret_key|private[_-]?key/i,
  };

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  /**
   * Detect all API key and credential exposures
   */
  detect(): DetectorResult {
    this.findings = [];
    this.generatedPocs = [];

    this.detectHardcodedApiKeys();
    this.detectKeysInConfigFiles();
    this.detectKeysInFunctionDefaults();
    this.detectKeysInComments();
    this.detectKeysInLogs();
    this.detectKeysInErrorMessages();
    this.detectDatabaseConnectionStrings();

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
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`Failed to export POC: ${errorMessage}`);
      }
    });

    return exportedFiles;
  }

  /**
   * Detect hardcoded API keys from major services
   */
  private detectHardcodedApiKeys(): void {
    const stringLiterals = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isStringLiteral(node)
    );

    stringLiterals.forEach((node) => {
      const text = (node as ts.StringLiteral).text;
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      // Skip if in detector logic
      if (this.isDetectorLogicString(line, text)) {
        return;
      }

      // Check against known service patterns
      for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
        if (pattern.test(text)) {
          const serviceType = this.extractServiceType(serviceName);
          const severity = this.isTestEnvironment() ? 'HIGH' : 'CRITICAL';

          this.findings.push({
            category: 'API_KEY_EXPOSURE',
            severity,
            title: `Hardcoded ${serviceType} Key`,
            description: `${serviceType} API key appears to be hardcoded in source code. This exposes the service to unauthorized access and potential abuse.`,
            file: this.filePath,
            line,
            column,
            code: text.substring(0, Math.min(50, text.length)),
            recommendation: `Move the ${serviceType} key to environment variables or a secrets manager. Use process.env or a library like dotenv.`,
          });

          break;
        }
      }
    });
  }

  /**
   * Detect keys in configuration files
   */
  private detectKeysInConfigFiles(): void {
    if (!this.isConfigFile()) {
      return;
    }

    const propertyAssignments = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isPropertyAssignment(node)
    );

    propertyAssignments.forEach((node) => {
      const propAssign = node as ts.PropertyAssignment;
      const propName = propAssign.name?.getText().toLowerCase() || '';
      const valueText = propAssign.initializer?.getText() || '';
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      const isKeyProperty = /api[_-]?key|secret|token|password|key|auth/i.test(propName);
      const hasHardcodedValue = /["'][\w\-\.]+["']/.test(valueText) && !this.isEnvironmentVariableReference(valueText);

      if (isKeyProperty && hasHardcodedValue) {
        this.findings.push({
          category: 'API_KEY_EXPOSURE',
          severity: 'CRITICAL',
          title: 'Hardcoded Key in Configuration File',
          description: 'API key or secret is hardcoded in a configuration file. This file may be committed to version control or deployed with the application.',
          file: this.filePath,
          line,
          column,
          code: propAssign.getText().substring(0, 60),
          recommendation: 'Use environment variables or a secrets manager. Remove from configuration files and add to .gitignore.',
        });

      }
    });
  }

  /**
   * Detect keys in function parameters and defaults
   */
  private detectKeysInFunctionDefaults(): void {
    const functions = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
    );

    functions.forEach((node) => {
      let parameters: ts.NodeArray<ts.ParameterDeclaration> | undefined;

      if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) {
        parameters = node.parameters;
      } else if (ts.isArrowFunction(node)) {
        parameters = node.parameters;
      }

      if (!parameters) return;

      parameters.forEach((param) => {
        if (param.initializer) {
          const defaultValue = param.initializer.getText();
          const paramName = param.name?.getText().toLowerCase() || '';
          const { line, column } = this.parser.getLineAndColumn(param.getStart());

          const isKeyParam = /api[_-]?key|secret|token|password/i.test(paramName);
          const hasHardcodedDefault = /["'][\w\-\.]{8,}["']/.test(defaultValue);

          if (isKeyParam && hasHardcodedDefault) {
            this.findings.push({
              category: 'API_KEY_EXPOSURE',
              severity: 'HIGH',
              title: 'Hardcoded Key in Function Default Parameter',
              description: 'Function parameter has a hardcoded API key or secret as default value.',
              file: this.filePath,
              line,
              column,
              code: param.getText().substring(0, 60),
              recommendation: 'Remove hardcoded defaults. Use dependency injection or environment variables instead.',
            });
          }
        }
      });
    });
  }

  /**
   * Detect keys exposed in comments
   */
  private detectKeysInComments(): void {
    const sourceText = this.sourceFile.getFullText();
    const lines = sourceText.split('\n');

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      
      // Skip detector logic lines
      if (this.isDetectorLogicString(lineNumber, line)) {
        return;
      }

      // Check for comments containing keys
      if (line.includes('//') || line.includes('/*') || line.includes('*')) {
        const comment = line.substring(line.indexOf('//') > -1 ? line.indexOf('//') : 
                                      line.indexOf('/*') > -1 ? line.indexOf('/*') : 0);
        
        for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
          if (pattern.test(comment)) {
            this.findings.push({
              category: 'API_KEY_EXPOSURE',
              severity: 'HIGH',
              title: `${this.extractServiceType(serviceName)} Key in Comment`,
              description: 'API key is exposed in code comment. Comments are included in source code and version control.',
              file: this.filePath,
              line: lineNumber,
              column: line.indexOf('//') > -1 ? line.indexOf('//') : line.indexOf('/*'),
              code: comment.substring(0, 60),
              recommendation: 'Remove all credentials from comments. Use environment variables or secrets managers.',
            });
            break;
          }
        }
      }
    });
  }

  /**
   * Detect keys in logs and error messages
   */
  private detectKeysInLogs(): void {
    const callExpressions = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isCallExpression(node)
    );

    callExpressions.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const funcName = callExpr.expression.getText().toLowerCase();

      // Check if this is a logging function
      if (/console\.(log|error|warn|info)|logger\.(log|error|warn|info)|debug|print/i.test(funcName)) {
        callExpr.arguments.forEach((arg) => {
          const argText = arg.getText();
          const { line, column } = this.parser.getLineAndColumn(arg.getStart());

          // Check if logging includes API key patterns
          for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
            if (pattern.test(argText)) {
              this.findings.push({
                category: 'API_KEY_EXPOSURE',
                severity: 'CRITICAL',
                title: `${this.extractServiceType(serviceName)} Key in Logs`,
                description: 'API key is being logged. Logs may be stored, transmitted, and accessed by multiple parties.',
                file: this.filePath,
                line,
                column,
                code: argText.substring(0, 60),
                recommendation: 'Remove credentials from log output. Implement logging filters or use a logging library that strips sensitive data.',
              });

              break;
            }
          }
        });
      }
    });
  }

  /**
   * Detect keys in error messages
   */
  private detectKeysInErrorMessages(): void {
    const stringLiterals = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isStringLiteral(node)
    );

    stringLiterals.forEach((node) => {
      const text = (node as ts.StringLiteral).text;
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      // Check if this looks like an error message containing a key
      const isErrorMessage = /error|Error|exception|Exception|failed|Failed|invalid|Invalid/.test(text);
      
      if (isErrorMessage) {
        for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
          if (pattern.test(text)) {
            this.findings.push({
              category: 'API_KEY_EXPOSURE',
              severity: 'HIGH',
              title: `${this.extractServiceType(serviceName)} Key in Error Message`,
              description: 'API key exposed in error message. Errors are often logged and displayed to users.',
              file: this.filePath,
              line,
              column,
              code: text.substring(0, 60),
              recommendation: 'Remove sensitive data from error messages. Log full errors internally but show sanitized messages to users.',
            });
            break;
          }
        }
      }
    });
  }

  /**
   * Detect database connection strings with credentials
   */
  private detectDatabaseConnectionStrings(): void {
    const stringLiterals = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isStringLiteral(node)
    );

    stringLiterals.forEach((node) => {
      const text = (node as ts.StringLiteral).text;
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      // Check for connection strings with credentials
      const dbConnectionPattern = /mongodb:\/\/[^:]+:[^@]+@|postgresql:\/\/[^:]+:[^@]+@|mysql:\/\/[^:]+:[^@]+@|mongodb\+srv:\/\/[^:]+:[^@]+@/i;
      const hasCredentials = /:\/\/[^:]+:.+@/.test(text);

      if (dbConnectionPattern.test(text) && hasCredentials && this.isInAssignmentContext(node)) {
        this.findings.push({
          category: 'API_KEY_EXPOSURE',
          severity: 'CRITICAL',
          title: 'Database Credentials in Connection String',
          description: 'Database connection string contains hardcoded username and password. Anyone with access to source code can access the database.',
          file: this.filePath,
          line,
          column,
          code: text.substring(0, 60),
          recommendation: 'Use environment variables for database credentials. Use MongoDB Atlas connection string helpers with IP whitelisting.',
        });

      }
    });
  }

  /**
   * Helper: Check if this is a test file
   */
  private isTestFile(): boolean {
    return /\.test\.ts|\.spec\.ts|__tests__|test|tests|fixtures/.test(this.filePath);
  }

  /**
   * Helper: Check if this is a configuration file
   */
  private isConfigFile(): boolean {
    return /config|\.env|settings|credentials/.test(this.filePath.toLowerCase());
  }

  /**
   * Helper: Check if this is a test environment
   */
  private isTestEnvironment(): boolean {
    return process.env.NODE_ENV === 'test' || this.isTestFile();
  }

  /**
   * Helper: Check if string is from detector logic
   */
  private isDetectorLogicString(line: number, text: string): boolean {
    const detectorLines = /API_KEY_PATTERNS|detectHardcodedApiKeys|isDetectorLogic/;
    return detectorLines.test(text) || (line >= 35 && line <= 60);
  }

  /**
   * Helper: Check if value references environment variable
   */
  private isEnvironmentVariableReference(text: string): boolean {
    return /process\.env|process\.env\[|env\[|__ENV__|import\.meta\.env/i.test(text);
  }

  /**
   * Helper: Check if node is in assignment context
   */
  private isInAssignmentContext(node: ts.Node): boolean {
    let parent = node.parent;
    while (parent) {
      if (ts.isBinaryExpression(parent) && 
          (parent as ts.BinaryExpression).operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        return true;
      }
      if (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent)) {
        return true;
      }
      parent = parent.parent;
    }
    return false;
  }

  /**
   * Helper: Extract service type from pattern name
   */
  private extractServiceType(patternName: string): string {
    const serviceMap: Record<string, string> = {
      aws_access_key: 'AWS Access',
      aws_secret_key: 'AWS Secret',
      stripe_live_key: 'Stripe Live',
      stripe_test_key: 'Stripe Test',
      stripe_public_key: 'Stripe Public',
      twilio_key: 'Twilio',
      twilio_auth: 'Twilio Auth',
      sendgrid_key: 'SendGrid',
      github_token: 'GitHub',
      firebase_key: 'Firebase',
      generic_api_key: 'API Key',
      generic_secret: 'Secret',
    };

    return serviceMap[patternName] || 'API';
  }
}
