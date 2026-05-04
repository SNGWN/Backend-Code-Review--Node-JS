import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept, PocGenerationRequest, PocGeneratorConfig } from '../poc/types';
import { Logger } from '../utils/logger';
import { getEnclosingScopeText } from '../utils/detectorLogic';

/**
 * JWT Token Validation Bypass Detector
 *
 * Detects common JWT vulnerabilities in TypeScript/JavaScript code:
 * - Missing signature verification (jwt.decode without jwt.verify)
 * - Algorithm confusion attacks (accepting 'none' algorithm)
 * - Key confusion attacks (RS256 accepted as HS256)
 * - Weak secret keys (<32 characters)
 * - No expiration/exp claim validation
 * - Replayed/cached tokens without fresh verification
 * - Missing kid (key ID) validation
 */
export class JwtBypassDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private generatedPocs: ProofOfConcept[] = [];
  private fileContent: string;

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
    this.fileContent = sourceFile.getFullText();
  }

  /**
   * Detects all JWT bypass vulnerabilities in the source file
   */
  detect(): DetectorResult {
    this.findings = [];
    this.generatedPocs = [];

    this.detectMissingSignatureVerification();
    this.detectAlgorithmConfusion();
    this.detectKeyConfusion();
    this.detectWeakSecrets();
    this.detectMissingExpValidation();
    this.detectCachedTokenUsage();
    this.detectMissingKidValidation();

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

  /**
   * Detects jwt.decode usage without jwt.verify (missing signature verification)
   */
  private detectMissingSignatureVerification(): void {
    const decodeNodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const propName = expr.name.text;
          const objName = this.getObjectName(expr.expression);
          return (
            (propName === 'decode' && objName === 'jwt') ||
            (propName === 'decode' && objName === 'JWT')
          );
        }
      }
      return false;
    });

    decodeNodes.forEach((node) => {
      const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const line = position.line + 1;
      const code = getEnclosingScopeText(node, this.sourceFile);

      // Check if there's corresponding verify call
      if (!this.hasVerifyCall(code)) {
        const finding: Finding = {
          category: 'AUTHENTICATION',
          severity: 'CRITICAL',
          title: 'JWT Signature Not Verified',
          description:
            'Token is decoded without verifying the signature. Attacker can forge arbitrary tokens.',
          file: this.filePath,
          line,
          column: position.character + 1,
          code,
          recommendation:
            'Always use jwt.verify() to validate the signature before trusting the token claims.',
          injectionType: 'JWT_MISSING_VERIFICATION',
        };

        this.findings.push(finding);
        this.generatePoc('missing-verification', finding, code);
      }
    });
  }

  /**
   * Detects algorithm confusion attacks (accepting 'none' algorithm)
   */
  private detectAlgorithmConfusion(): void {
    const verifyNodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const propName = expr.name.text;
          const objName = this.getObjectName(expr.expression);
          return (propName === 'verify' && (objName === 'jwt' || objName === 'JWT'));
        }
      }
      return false;
    });

    verifyNodes.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const line = position.line + 1;
      const code = this.getCodeSnippet(line);

      // Check for algorithm options - options are the 3rd argument (index 2)
      if (callExpr.arguments.length > 2) {
        const optionsArg = callExpr.arguments[2];
        const optionsText = optionsArg.getText();

        // Check if algorithms array includes 'none'
        if (
          optionsText.includes('none') ||
          optionsText.includes("'none'") ||
          optionsText.includes('"none"')
        ) {
          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'CRITICAL',
            title: 'Algorithm Confusion Attack - None Algorithm Allowed',
            description:
              'JWT verification allows the "none" algorithm. Attacker can create unsigned tokens that pass verification.',
            file: this.filePath,
            line,
            column: position.character + 1,
            code,
            recommendation:
              'Never allow the "none" algorithm. Explicitly specify allowed algorithms: { algorithms: ["HS256"] }',
            injectionType: 'JWT_ALGORITHM_CONFUSION',
          };

          this.findings.push(finding);
          this.generatePoc('algorithm-confusion', finding, code);
        }

        // Check if no algorithms are specified (allows any algorithm)
        if (!optionsText.includes('algorithm')) {
          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'HIGH',
            title: 'Missing Algorithm Specification',
            description:
              'JWT verification does not explicitly specify allowed algorithms, making it vulnerable to algorithm substitution attacks.',
            file: this.filePath,
            line,
            column: position.character + 1,
            code,
            recommendation:
              'Explicitly specify allowed algorithms in verify options: { algorithms: ["HS256"] }',
            injectionType: 'JWT_MISSING_ALGORITHM_SPEC',
          };

          this.findings.push(finding);
          this.generatePoc('missing-algorithm-spec', finding, code);
        }
      }
    });
  }

  /**
   * Detects key confusion attacks (RS256 key used with HS256)
   */
  private detectKeyConfusion(): void {
    const verifyNodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const propName = expr.name.text;
          const objName = this.getObjectName(expr.expression);
          return (propName === 'verify' && (objName === 'jwt' || objName === 'JWT'));
        }
      }
      return false;
    });

    verifyNodes.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const line = position.line + 1;
      const code = this.getCodeSnippet(line);

      // Check if using public key for HS256
      if (callExpr.arguments.length > 1) {
        const keyArg = callExpr.arguments[1];
        const keyText = keyArg.getText();

        if (
          (keyText.includes('publicKey') || keyText.includes('public_key')) &&
          code.includes('HS256')
        ) {
          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'CRITICAL',
            title: 'Key Confusion Attack - Public Key with HMAC',
            description:
              'Algorithm is HS256 (HMAC) but using a public key as the secret. Attacker can forge tokens using the public key.',
            file: this.filePath,
            line,
            column: position.character + 1,
            code,
            recommendation:
              'Use symmetric algorithms (HS256) with a private secret, or asymmetric algorithms (RS256) with private/public keys. Never mix them.',
            injectionType: 'JWT_KEY_CONFUSION',
          };

          this.findings.push(finding);
          this.generatePoc('key-confusion', finding, code);
        }
      }
    });
  }

  /**
   * Detects weak JWT secrets (less than 32 characters)
   */
  private detectWeakSecrets(): void {
    const variableDeclarations = ASTVisitor.findNodes(this.sourceFile, (node): boolean => {
      return (
        ts.isVariableDeclaration(node) &&
        node.initializer !== undefined &&
        ts.isStringLiteral(node.initializer)
      );
    });

    variableDeclarations.forEach((node) => {
      const varDecl = node as ts.VariableDeclaration;
      const varName = (varDecl.name as ts.Identifier).text;

      if (
        varName.toLowerCase().includes('secret') ||
        varName.toLowerCase().includes('key') ||
        varName.toLowerCase().includes('token')
      ) {
        const initializer = varDecl.initializer as ts.StringLiteral;
        const secretValue = initializer.text;

        if (secretValue.length < 32) {
          const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
          const line = position.line + 1;
          const code = this.getCodeSnippet(line);

          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'HIGH',
            title: 'Weak JWT Secret Key',
            description: `JWT secret key is only ${secretValue.length} characters long. Should be at least 32 characters (256 bits) for HMAC.`,
            file: this.filePath,
            line,
            column: position.character + 1,
            code,
            recommendation:
              'Use a cryptographically random secret of at least 32 characters (256 bits). Use: crypto.randomBytes(32).toString("hex")',
            injectionType: 'JWT_WEAK_SECRET',
          };

          this.findings.push(finding);
          this.generatePoc('weak-secret', finding, code);
        }
      }
    });
  }

  /**
   * Detects missing expiration (exp) claim validation
   */
  private detectMissingExpValidation(): void {
    const verifyNodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const propName = expr.name.text;
          const objName = this.getObjectName(expr.expression);
          return (propName === 'verify' && (objName === 'jwt' || objName === 'JWT'));
        }
      }
      return false;
    });

    verifyNodes.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const line = position.line + 1;
      const code = this.getCodeSnippet(line);

      if (callExpr.arguments.length > 2) {
        const optionsArg = callExpr.arguments[2];
        const optionsText = optionsArg.getText();

        // Check if ignoreExpiration is set to true or if no ignoreExpiration check
        if (optionsText.includes('ignoreExpiration: true') || optionsText.includes('ignoreExpiration:true')) {
          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'HIGH',
            title: 'JWT Expiration Check Disabled',
            description:
              'Verification ignores token expiration time. Old/revoked tokens will be accepted indefinitely.',
            file: this.filePath,
            line,
            column: position.character + 1,
            code,
            recommendation: 'Remove ignoreExpiration flag and validate exp claim. Set: { ignoreExpiration: false }',
            injectionType: 'JWT_MISSING_EXP_VALIDATION',
          };

          this.findings.push(finding);
          this.generatePoc('missing-exp-validation', finding, code);
        }
      }
    });
  }

  /**
   * Detects cached token usage without fresh verification
   */
  private detectCachedTokenUsage(): void {
    // Look for patterns where decoded token is cached or stored
    const assignments = ASTVisitor.findNodes(this.sourceFile, (node) => {
      return ts.isBinaryExpression(node);
    });

    assignments.forEach((node) => {
      const binExpr = node as ts.BinaryExpression;
      const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const line = position.line + 1;
      const code = this.getCodeSnippet(line);

      const leftText = binExpr.left.getText();
      const rightText = binExpr.right.getText();

      // Look for cache[token] = decoded pattern
      if (
        leftText.includes('cache') &&
        (rightText.includes('decode') || rightText.includes('jwt'))
      ) {
        const finding: Finding = {
          category: 'AUTHENTICATION',
          severity: 'HIGH',
          title: 'Cached JWT Without Expiration Validation',
          description:
            'Decoded JWT is cached without proper expiration validation. Revoked or expired tokens may still be accepted.',
          file: this.filePath,
          line,
          column: position.character + 1,
          code,
          recommendation:
            'Always verify JWT freshness. Implement token blacklist/revocation checks and never cache decoded tokens indefinitely.',
          injectionType: 'JWT_CACHED_WITHOUT_VALIDATION',
        };

        this.findings.push(finding);
        this.generatePoc('cached-token', finding, code);
      }
    });
  }

  /**
   * Detects missing key ID (kid) validation
   */
  private detectMissingKidValidation(): void {
    const verifyNodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const propName = expr.name.text;
          const objName = this.getObjectName(expr.expression);
          return (propName === 'verify' && (objName === 'jwt' || objName === 'JWT'));
        }
      }
      return false;
    });

    verifyNodes.forEach((node) => {
      const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
      const line = position.line + 1;
      const code = getEnclosingScopeText(node, this.sourceFile);

      // Check if kid claim is validated
      if ((node as ts.CallExpression).arguments.length > 0) {
        // Check if kid validation is missing
        if (!this.hasKidValidation(code)) {
          const finding: Finding = {
            category: 'AUTHENTICATION',
            severity: 'MEDIUM',
            title: 'Missing Key ID (kid) Validation',
            description:
              'JWT key ID (kid) claim is not validated. Attacker could specify an arbitrary kid to confuse key selection logic.',
            file: this.filePath,
            line,
            column: position.character + 1,
            code,
            recommendation:
              'Always validate the kid claim and ensure it matches an expected key ID in your key store.',
            injectionType: 'JWT_MISSING_KID_VALIDATION',
          };

          this.findings.push(finding);
          this.generatePoc('missing-kid-validation', finding, code);
        }
      }
    });
  }

  /**
   * Helper: Check if code has jwt.verify() call
   */
  private hasVerifyCall(code: string): boolean {
    return /jwt\.verify|JWT\.verify|verifyToken|validateToken|passport\.authenticate|authmiddleware|requireauth|ensureauth/.test(code);
  }

  /**
   * Helper: Check if code has kid validation
   */
  private hasKidValidation(code: string): boolean {
    return /kid|key.*id|keyId|key_id/.test(code);
  }

  /**
   * Helper: Get object name from property access expression
   */
  private getObjectName(expr: ts.Expression): string {
    if (ts.isIdentifier(expr)) {
      return expr.text;
    }
    if (ts.isPropertyAccessExpression(expr)) {
      return expr.name.text;
    }
    return '';
  }

  /**
   * Helper: Get code snippet for a line
   */
  private getCodeSnippet(line: number): string {
    const lines = this.fileContent.split('\n');
    return lines[line - 1] || '';
  }

  /**
   * Helper: Generate POC for finding
   */
  private generatePoc(
    vulnerabilityType: string,
    finding: Finding,
    code: string
  ): void {
    const poc: ProofOfConcept = {
      id: `jwt-${vulnerabilityType}-${finding.line}-${Date.now()}`,
      title: finding.title,
      description: finding.description,
      vulnerabilityType: 'JWT_BYPASS',
      severity: finding.severity,
      cvssScore: finding.severity === 'CRITICAL' ? 9.1 : finding.severity === 'HIGH' ? 8.2 : 6.4,
      steps: [
        {
          stepNumber: 1,
          actor: 'attacker',
          description: 'Collect a valid JWT-bearing request to the target API endpoint.',
          payload: 'Authorization: Bearer <token>',
          expectedResult: 'Request is accepted when token is valid.',
        },
        {
          stepNumber: 2,
          actor: 'attacker',
          description: 'Craft a malicious token exploiting the detected JWT validation weakness.',
          payload: 'Manipulated JWT (e.g., alg:none, weak-secret forgery, or mismatched key algorithm)',
          expectedResult: 'Forged token generated successfully.',
        },
        {
          stepNumber: 3,
          actor: 'backend',
          description: 'Send the forged token to a protected endpoint and observe authorization bypass.',
          codeSnippet: code,
          filePath: this.filePath,
          lineNumber: finding.line,
          expectedResult: 'Protected endpoint returns success for unauthorized token.',
        },
      ],
      codeFlow: {
        diagram: '[Attacker Token] -> [JWT Verify/Decode] -> [Auth Decision] -> [Protected Resource]',
        components: [
          { id: 'token', name: 'JWT Input', type: 'input', isVulnerable: true, location: `${this.filePath}:${finding.line}` },
          { id: 'verify', name: 'Token Validation', type: 'validation', isVulnerable: true },
          { id: 'decision', name: 'Auth Decision', type: 'processing', isVulnerable: true },
          { id: 'resource', name: 'Protected Endpoint', type: 'output' },
        ],
        connections: [
          { from: 'token', to: 'verify', label: 'token', isVulnerable: true },
          { from: 'verify', to: 'decision', label: 'claims trusted', isVulnerable: true },
          { from: 'decision', to: 'resource', label: 'access granted', isVulnerable: true },
        ],
      },
      rootCause: 'JWT validation accepts unsafe algorithms, weak keys, or incomplete verification checks.',
      businessImpact: 'Attackers can impersonate users/admins and access protected data or actions.',
      technicalImpact: 'Authentication trust boundary is bypassed by forged or replayed JWTs.',
      payloads: [
        {
          name: 'JWT bypass attempt',
          content: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.',
          contentType: 'jwt',
          description: 'Unsigned JWT using alg=none to test weak verification.',
          expectedOutput: 'If vulnerable, endpoint accepts token and returns protected response.',
          difficulty: 'easy',
          successRate: 70,
        },
      ],
      remediationCode: `jwt.verify(token, key, {\n  algorithms: ['HS256'],\n  ignoreExpiration: false,\n  complete: false,\n});`,
      remediationDescription: 'Enforce strict JWT verification with explicit algorithms, strong keys, expiration checks, and kid/key validation.',
      owaspCategory: 'A07:2021 - Identification and Authentication Failures',
      generatedAt: new Date(),
      pocVersion: '2.0',
    };

    this.generatedPocs.push(poc);
  }
}
