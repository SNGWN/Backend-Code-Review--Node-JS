import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept } from '../poc/types';
import { Logger } from '../utils/logger';
import {
  isEnumLikeLiteral,
  isPathLikeLiteral,
  isStringLiteralInMetadataContext,
} from '../utils/detectorLogic';

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
  private readonly GENERIC_CREDENTIAL_NAME_PATTERN =
    /(api[_-]?key|apikey|secret|private[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret|password)/i;

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
    this.detectEnvVarFallbackSecrets();

    return { findings: this.findings };
  }

  /**
   * BCR-KEY-008: a secret-like environment variable falling back to a hardcoded literal,
   * e.g. `process.env.JWT_SECRET || 'dev-secret'`. When the env var is unset in any
   * environment the service silently runs on the attacker-knowable default — a classic
   * staging/prod misconfiguration that bypasses signature/encryption guarantees.
   */
  private detectEnvVarFallbackSecrets(): void {
    const SECRET_ENV = /(secret|token|key|password|passwd|pwd|credential|private[_-]?key|api[_-]?key|jwt|signing|encryption|salt|hmac|client[_-]?secret)/i;
    const binaries = ASTVisitor.findNodes(
      this.sourceFile,
      (node) =>
        ts.isBinaryExpression(node) &&
        (node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
    ) as ts.BinaryExpression[];

    binaries.forEach((bin) => {
      // LHS must be a `process.env.X` / `process.env['X']` access for a secret-like X.
      const leftText = bin.left.getText(this.sourceFile);
      if (!/process\.env\b/.test(leftText)) return;
      if (!SECRET_ENV.test(leftText)) return;

      // RHS must be a non-empty string literal that is not an obvious placeholder.
      const right = bin.right;
      if (!(ts.isStringLiteral(right) || ts.isNoSubstitutionTemplateLiteral(right))) return;
      const literal = right.text;
      if (literal.length < 3) return; // '' or trivial placeholders aren't a usable secret
      if (/^(undefined|null|none|false|true|0)$/i.test(literal)) return;

      const { line, column } = this.parser.getLineAndColumn(bin.getStart());
      this.findings.push({
        ruleId: 'BCR-KEY-008',
        category: 'API_KEY_EXPOSURE',
        severity: 'HIGH',
        title: 'Hardcoded Secret as Environment-Variable Fallback',
        description: `A secret-like environment variable falls back to the hardcoded literal "${literal.length > 32 ? literal.slice(0, 29) + '…' : literal}". If the env var is unset, the service runs on this known default.`,
        file: this.filePath,
        line,
        column,
        code: bin.getText(this.sourceFile).substring(0, 120),
        recommendation: 'Fail closed when a required secret is missing (throw on startup) instead of defaulting to a literal.',
      });
    });
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
        Logger.error('Failed to export POC', { error: errorMessage });
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
      const stringLiteral = node as ts.StringLiteral;
      const text = stringLiteral.text;
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      if (this.shouldIgnoreStringLiteral(stringLiteral, text)) {
        return;
      }

      // Check against known service patterns
      for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
        if (serviceName.startsWith('generic_') && !this.isLikelyGenericCredential(stringLiteral, text)) {
          continue;
        }

        if (pattern.test(text)) {
          const serviceType = this.extractServiceType(serviceName);
          const severity = this.isTestEnvironment() ? 'HIGH' : 'CRITICAL';

          this.findings.push({
            ruleId: 'BCR-KEY-001',
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
      const initializer = propAssign.initializer;
      const valueText = initializer?.getText() || '';
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      // Tightened: the property name must read like a credential container (not just
      // "key" — which fires on countless safe shapes like `{ keyExtractor, partitionKey }`).
      const isKeyProperty = /\b(api[_-]?key|apikey|secret|access[_-]?token|refresh[_-]?token|password|passwd|pwd|client[_-]?secret|private[_-]?key|jwt[_-]?secret)\b/i.test(propName);
      if (!isKeyProperty) return;

      // The value must be a non-env-var string literal that itself looks like a secret.
      if (this.isEnvironmentVariableReference(valueText)) return;
      if (!initializer || !ts.isStringLiteral(initializer)) return;
      if (!this.looksLikeSecretValue(initializer.text)) return;

      this.findings.push({
        ruleId: 'BCR-KEY-002',
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
              ruleId: 'BCR-KEY-003',
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

    // Compute the line ranges that fall inside JSDoc blocks whose tags signal
    // documentation/example content (`@swagger`, `@openapi`, `@example`). Real-world
    // OpenAPI/Swagger annotations routinely embed sample JWTs and access tokens — those
    // are documentation, not exposed secrets.
    const docCommentRanges = computeDocCommentRanges(sourceText);

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      if (docCommentRanges.some((range) => lineNumber >= range.start && lineNumber <= range.end)) {
        return;
      }

      // Skip detector logic lines
      if (this.isDetectorLogicString(line)) {
        return;
      }

      // Check for comments containing keys
      if (line.includes('//') || line.includes('/*') || line.includes('*')) {
        const comment = line.substring(line.indexOf('//') > -1 ? line.indexOf('//') :
                                      line.indexOf('/*') > -1 ? line.indexOf('/*') : 0);
        
        for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
          if (!this.matchesCredentialText(comment, serviceName, pattern)) {
            continue;
          }

          this.findings.push({
            ruleId: 'BCR-KEY-004',
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

      // Check if this is a logging function. `\b` anchors `debug`/`print` so they don't match
      // inside `sprintf`, `fingerprint`, `blueprint`, `debugger`, etc.
      if (/console\.(log|error|warn|info|debug)|logger\.(log|error|warn|info|debug|trace)|\b(debug|println?|printf)\b/i.test(funcName)) {
        callExpr.arguments.forEach((arg) => {
          const argText = arg.getText();
          const { line, column } = this.parser.getLineAndColumn(arg.getStart());

          const serviceName = this.getLoggedCredentialServiceName(arg);
          if (!serviceName) {
            return;
          }

          this.findings.push({
            ruleId: 'BCR-KEY-005',
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
          if (!this.matchesCredentialText(text, serviceName, pattern)) {
            continue;
          }

          this.findings.push({
            ruleId: 'BCR-KEY-006',
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
          ruleId: 'BCR-KEY-007',
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
  private isDetectorLogicString(text: string): boolean {
    return /API_KEY_PATTERNS|detectHardcodedApiKeys|isDetectorLogic|extractServiceType/.test(text);
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

  private shouldIgnoreStringLiteral(node: ts.StringLiteral, text: string): boolean {
    return (
      this.isDetectorLogicString(text) ||
      isStringLiteralInMetadataContext(node) ||
      isEnumLikeLiteral(text) ||
      isPathLikeLiteral(text)
    );
  }

  private isLikelyGenericCredential(node: ts.StringLiteral, text: string): boolean {
    if (!this.isInAssignmentContext(node)) {
      return false;
    }

    const contextName = this.getCredentialContextName(node);
    if (!contextName || !this.GENERIC_CREDENTIAL_NAME_PATTERN.test(contextName)) {
      return false;
    }

    return this.looksLikeSecretValue(text);
  }

  private matchesCredentialText(
    text: string,
    serviceName: string,
    pattern: RegExp
  ): boolean {
    if (!serviceName.startsWith('generic_')) {
      return pattern.test(text);
    }

    return this.findInlineGenericCredential(text) !== null;
  }

  private getLoggedCredentialServiceName(arg: ts.Expression): string | null {
    const argText = arg.getText();

    for (const [serviceName, pattern] of Object.entries(this.API_KEY_PATTERNS)) {
      if (serviceName.startsWith('generic_')) {
        continue;
      }

      if (pattern.test(argText)) {
        return serviceName;
      }
    }

    const identifierName = this.getSensitiveIdentifierName(arg);
    if (identifierName && this.GENERIC_CREDENTIAL_NAME_PATTERN.test(identifierName)) {
      return /api[_-]?key|apikey/i.test(identifierName) ? 'generic_api_key' : 'generic_secret';
    }

    const templateText = ts.isTemplateExpression(arg) ? arg.getText() : argText;
    const inlineGeneric = this.findInlineGenericCredential(templateText);
    if (inlineGeneric) {
      return inlineGeneric.type;
    }

    return null;
  }

  private getSensitiveIdentifierName(expression: ts.Expression): string | null {
    if (ts.isIdentifier(expression)) {
      return expression.text;
    }

    if (ts.isPropertyAccessExpression(expression)) {
      return expression.name.text;
    }

    if (
      ts.isElementAccessExpression(expression) &&
      ts.isStringLiteralLike(expression.argumentExpression)
    ) {
      return expression.argumentExpression.text;
    }

    if (ts.isTemplateExpression(expression)) {
      for (const span of expression.templateSpans) {
        const nestedName = this.getSensitiveIdentifierName(span.expression);
        if (nestedName) {
          return nestedName;
        }
      }
    }

    return null;
  }

  private getCredentialContextName(node: ts.Node): string | null {
    let current: ts.Node | undefined = node;

    while (current?.parent) {
      const parent = current.parent;

      if (ts.isVariableDeclaration(parent) && parent.initializer === current) {
        return parent.name.getText(this.sourceFile);
      }

      if (ts.isPropertyAssignment(parent) && parent.initializer === current) {
        return parent.name.getText(this.sourceFile);
      }

      if (ts.isParameter(parent) && parent.initializer === current) {
        return parent.name.getText(this.sourceFile);
      }

      current = parent;
    }

    return null;
  }

  private looksLikeSecretValue(text: string): boolean {
    if (text.length < 12 || /\s/.test(text)) return false;
    // Reject obvious label / header / kebab-word shapes.
    if (/^[a-z]+(?:[-_][a-z]+)+$/i.test(text) && !/\d/.test(text)) return false;
    if (/^[xX]-[A-Za-z][A-Za-z0-9-]*$/.test(text)) return false;
    if (/^[A-Z][A-Za-z0-9]*(?:[-_][A-Z][A-Za-z0-9]*)+$/.test(text) && !/\d/.test(text)) return false;
    // Sentinel words.
    if (/^(changeme|your[_-]?(secret|key|token)|placeholder|example|sample|test|todo)([_-].*)?$/i.test(text)) {
      return false;
    }

    if (/^[A-Fa-f0-9]{24,}$/.test(text)) return true;

    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[_./+=-]/].filter((pattern) => pattern.test(text)).length;
    if (classes >= 3 && (/\d/.test(text) || text.length >= 20)) return true;

    return /[A-Za-z0-9._+=/-]{20,}/.test(text) && /\d/.test(text);
  }

  private findInlineGenericCredential(
    text: string
  ): { type: 'generic_api_key' | 'generic_secret'; value: string } | null {
    const inlineMatch = /(?:api[_-]?key|apikey|secret|token|password|client[_-]?secret)\b[^:=\n]{0,20}[:=]\s*['"`]?([A-Za-z0-9._+=/-]{12,})/i.exec(
      text
    );

    if (!inlineMatch) {
      return null;
    }

    const value = inlineMatch[1];
    if (!this.looksLikeSecretValue(value)) {
      return null;
    }

    return {
      type: /api[_-]?key|apikey/i.test(inlineMatch[0]) ? 'generic_api_key' : 'generic_secret',
      value,
    };
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

/**
 * Returns line ranges (1-based, inclusive) that fall inside a JSDoc-style block whose
 * leading tags indicate documentation / API spec content. Used by `BCR-KEY-004` to
 * suppress findings inside swagger / openapi / @example blocks where sample JWTs and
 * placeholder tokens are routine.
 */
function computeDocCommentRanges(source: string): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  const blockRegex = /\/\*\*([\s\S]*?)\*\//g;
  let match: RegExpExecArray | null;
  while ((match = blockRegex.exec(source)) !== null) {
    const body = match[1];
    if (!/@(swagger|openapi|example|api|exampleresponse|exampleobject)\b/i.test(body)) continue;
    const before = source.slice(0, match.index);
    const startLine = before.split('\n').length;
    const endLine = startLine + match[0].split('\n').length - 1;
    ranges.push({ start: startLine, end: endLine });
  }
  return ranges;
}
