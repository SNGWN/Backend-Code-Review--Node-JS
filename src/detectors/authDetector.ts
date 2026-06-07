import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { getEnclosingScopeText } from '../utils/detectorLogic';
/**
 * Best-effort heuristic for "this string looks like an actual secret, not a placeholder."
 * Rejects: short values, all-lowercase words, obvious sentinels ("changeme", "your-secret-here").
 * Accepts: hex (16+), base64-ish (16+ with mixed-case/digits), high-entropy mixed-class.
 */
function looksLikeRealSecret(value: string): boolean {
  if (!value || value.length < 8) return false;

  // Sentinels and obvious placeholders.
  if (/^(changeme|your[_-]?(secret|key|token)|placeholder|example|sample|test|todo|fix(me)?)([_-].*)?$/i.test(value)) {
    return false;
  }

  // Kebab/snake words ("my-cool-key", "session-id-header") — no digits, just labels.
  if (/^[a-z]+(?:[-_][a-z]+)*$/i.test(value) && !/\d/.test(value)) return false;

  // HTTP header / Content-Type / event-name shapes — capitalised words with hyphens, no digits.
  if (/^[A-Z][A-Za-z0-9]*(?:[-_][A-Z][A-Za-z0-9]*)+$/.test(value) && !/\d/.test(value)) return false;

  // Common service-name shapes ("auth-token", "api-key", "x-request-id").
  if (/^[xX]-[A-Za-z][A-Za-z0-9-]*$/.test(value)) return false;

  // High-entropy positive signals.
  if (/^[A-Fa-f0-9]{16,}$/.test(value)) return true;
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(value)) return true;

  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[._+=/-]/].filter((pattern) => pattern.test(value)).length;
  // Require digits OR length>=20 for the mixed-class branch — "X-Secret-Header"-style
  // labels never hit this anymore.
  return classes >= 3 && value.length >= 12 && (/\d/.test(value) || value.length >= 20);
}

/**
 * A password container can hold short, low-entropy strings ("admin123") that are still
 * exploitable. We accept anything non-trivial and reject only sentinels / single tokens
 * that look like placeholders.
 */
function looksLikeHardcodedPassword(value: string): boolean {
  if (!value || value.length < 4) return false;
  if (/^(changeme|placeholder|example|sample|todo|none|null|undefined|password)$/i.test(value)) {
    return false;
  }
  return true;
}
import { HardcodedSecretPocGenerator } from '../poc/templates/HardcodedSecretPocGenerator';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept, PocGenerationRequest, PocGeneratorConfig } from '../poc/types';
import { Logger } from '../utils/logger';
import {
  getRouteHandlerContexts,
  hasAuthenticationProtection,
  isEnumLikeLiteral,
  isPathLikeLiteral,
  isSensitiveRouteContext,
  isStringLiteralInMetadataContext,
} from '../utils/detectorLogic';

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
 * result.findings; // Array of authentication issues
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
        const errorMessage = error instanceof Error ? error.message : String(error);
        Logger.error(`Failed to export POC ${poc.id}`, { error: errorMessage });
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

      // Only flag tokens that are actually request-derived. A bare `.token` on some config object
      // or DTO is not a JWT-verification concern; this gate removes the dominant false positive.
      const scope = getEnclosingScopeText(access, this.sourceFile);
      const isRequestDerived =
        /\b(req|request)\.(headers|cookies|query|body|signedcookies)\b|authorization|bearer|x-access-token|getauthtoken/i.test(scope);
      if (!isRequestDerived) return;

      // Verification must be found in the enclosing FUNCTION scope, not just the immediate parent
      // node — `const t = req.headers.token; ...; jwt.verify(t, secret)` is safe but the parent of
      // the `.token` access shows no verification.
      if (this.hasTokenVerification(scope)) return;

      const { line, column } = this.parser.getLineAndColumn(access.getStart());
      this.findings.push({
        ruleId: 'BCR-AUTH-001',
        category: 'AUTHENTICATION',
        severity: 'CRITICAL',
        confidence: 'FIRM',
        verify: 'Confirm the token reaches a sink (claims read / authorization) before a jwt.verify() / signature check.',
        title: 'Unverified Token Usage',
        description: 'A request-derived token is used without a prior signature verification in the same function. Attackers can forge token claims.',
        file: this.filePath,
        line,
        column,
        code: access.getText(),
        recommendation: 'Verify and validate the token before using it. Use middleware like jwt.verify() with explicit algorithms.',
      });
    });
  }

  private hasTokenVerification(scopeText: string): boolean {
    // `decode` and `check` were removed: jwt.decode() does NOT verify the signature (it is itself a
    // vuln signal), and `check` is too generic. Real verification is jwt.verify / passport /
    // a named verify/validate/authenticate routine.
    return /\bjwt\.verify\b|\bverify(token|jwt|signature)?\b|\bvalidate(token|jwt)?\b|passport\.authenticate|\bauthenticate(token|jwt)?\b|express-jwt|jwks/i.test(
      scopeText
    );
  }

  private detectWeakTokenHandling(): void {
    const stringLiterals = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isStringLiteral(node)
    );

    stringLiterals.forEach((node) => {
      const stringLiteral = node as ts.StringLiteral;
      const rawText = stringLiteral.text;
      const text = rawText.toLowerCase();
      const { line, column } = this.parser.getLineAndColumn(node.getStart());

      if (
        this.isDetectorDocString(text) ||
        isStringLiteralInMetadataContext(stringLiteral) ||
        isEnumLikeLiteral(rawText) ||
        isPathLikeLiteral(rawText)
      ) {
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
          ruleId: 'BCR-AUTH-002',
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
    const routes = getRouteHandlerContexts(this.sourceFile, this.parser);

    routes.forEach((route) => {
      if (!isSensitiveRouteContext(route) || hasAuthenticationProtection(route)) {
        return;
      }

      this.findings.push({
        ruleId: 'BCR-AUTH-003',
        category: 'AUTHENTICATION',
        severity: 'HIGH',
        title: 'Sensitive Function Without Auth Guard',
        description: `Route '${route.path}' performs sensitive operations without authentication checks.`,
        file: this.filePath,
        line: route.line,
        column: 1,
        code: route.routeText.substring(0, 100),
        recommendation: 'Add authentication middleware or verified identity checks before executing sensitive route logic.',
      });
    });
  }

  private detectHardcodedSecrets(): void {
    // Skip test files. `const password = 'password1'` is a routine Jest spec, not a
    // hardcoded production secret. Real cred-leak shapes (`process.env.FOO = 'sk_live…'`)
    // are still caught elsewhere — this rule's signal-to-noise is too low in test files.
    // Filename-only check (don't match fixtures-under-tests/ paths).
    if (/\.(test|spec)\.tsx?$|\/__tests__\//.test(this.filePath.toLowerCase())) {
      return;
    }
    const varDeclarations = ASTVisitor.findVariableDeclarations(this.sourceFile);
    // Stricter than StringHelper.containsSensitivePatterns: we deliberately exclude
    // benign identifier names ("email", "username", "userId") that fire on every login
    // form without indicating a hardcoded secret. The variable name must read like a
    // *credential* container, not just any PII.
    const credentialNamePattern = /(secret|password|passwd|pwd|token|apikey|api[_-]key|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret|jwt[_-]?secret|encryption[_-]?key|signing[_-]?key|cipher[_-]?key)/i;

    varDeclarations.forEach((decl) => {
      const varName = ASTVisitor.getIdentifierName(decl.name);
      if (!varName || !credentialNamePattern.test(varName)) return;
      if (!decl.initializer || !ts.isStringLiteral(decl.initializer)) return;

      const value = decl.initializer.text;
      if (
        isStringLiteralInMetadataContext(decl.initializer) ||
        isEnumLikeLiteral(value) ||
        isPathLikeLiteral(value)
      ) {
        return;
      }

      // Password containers get a looser test: real passwords can be short and
      // single-class. Other credential names still need the full entropy/format check.
      const isPasswordContainer = /(password|passwd|pwd)/i.test(varName);
      const passes = isPasswordContainer
        ? looksLikeHardcodedPassword(value)
        : looksLikeRealSecret(value);

      if (!passes) return;

      const { line, column } = this.parser.getLineAndColumn(decl.getStart());
      const code = decl.getText();
      const finding: Finding = {
        ruleId: 'BCR-AUTH-004',
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
      this.generateSecretPoc(finding, code, line);
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
        Logger.success(`POC generated for hardcoded secret at line ${line}`);
      } else {
        Logger.warn('Failed to generate hardcoded secret POC', { error: result.error, line });
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error('Error generating POC for hardcoded secret', { error: errorMessage, line });
    }
  }
}
