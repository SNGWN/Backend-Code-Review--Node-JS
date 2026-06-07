import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';

export class CryptoWeaknessDetector {
  private findings: Finding[] = [];
  private generatedPocs: ProofOfConcept[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;

  constructor(filePath: string, sourceFile: ts.SourceFile, _parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
  }

  detect(): DetectorResult {
    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isCallExpression(node)) {
        this.checkWeakHashing(node);
        this.checkPredictableTokens(node);
        this.checkHardcodedKeys(node);
      }
      if (ts.isBinaryExpression(node)) {
        this.checkTimingUnsafeComparison(node);
      }
    });
    return { findings: this.findings };
  }

  /**
   * Timing-unsafe comparison of a secret/signature with `===`/`==`. The dominant real-world
   * impact is webhook signature bypass (Stripe/GitHub/Svix HMAC) and token/HMAC checks that leak
   * the secret byte-by-byte through response-time differences. `crypto.timingSafeEqual` is the fix.
   */
  private checkTimingUnsafeComparison(node: ts.BinaryExpression): void {
    const op = node.operatorToken.kind;
    if (
      op !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
      op !== ts.SyntaxKind.ExclamationEqualsEqualsToken &&
      op !== ts.SyntaxKind.EqualsEqualsToken &&
      op !== ts.SyntaxKind.ExclamationEqualsToken
    ) {
      return;
    }
    const SECRET_NAME = /signature|\bsig\b|hmac|digest|\bmac\b|\bhash\b|token|secret|otp|\bnonce\b|csrf|checksum|expectedhash|computedhash/i;
    const leftText = node.left.getText(this.sourceFile);
    const rightText = node.right.getText(this.sourceFile);
    const leftSecret = SECRET_NAME.test(leftText);
    const rightSecret = SECRET_NAME.test(rightText);
    if (!leftSecret && !rightSecret) return;

    // A literal string on one side (`x === 'true'`) is not a secret comparison; skip.
    if (ts.isStringLiteral(node.left) || ts.isStringLiteral(node.right)) return;

    // Stronger signal when one side is a crypto computation (createHmac/digest/sign).
    const computed = /createHmac|createHash|\.digest\(|\.sign\(|crypto\./i.test(leftText + rightText);
    const position = this.sourceFile.getLineAndCharacterOfPosition(node.getStart());
    this.findings.push({
      ruleId: 'BCR-CRYPTO-006',
      category: 'CRYPTO_WEAKNESS',
      severity: 'HIGH',
      confidence: computed ? 'FIRM' : 'TENTATIVE',
      verify: 'Confirm both sides are secret material (signature/HMAC/token) rather than unrelated values.',
      title: 'Timing-Unsafe Secret/Signature Comparison',
      description: 'A secret, signature, HMAC, or token is compared with === / ==, which short-circuits on the first differing byte and leaks the value through timing. Enables webhook signature bypass and token brute-force.',
      file: this.filePath,
      line: position.line + 1,
      column: position.character + 1,
      code: node.getText(this.sourceFile).substring(0, 120),
      recommendation: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) after a length check, or a library verify() (e.g. stripe.webhooks.constructEvent).',
    });
  }

  private checkWeakHashing(node: ts.CallExpression): void {
    const funcName = this.getCallExpressionName(node);
    let algorithm: string | null = null;
    let viaHmac = false;

    // Bare md5()/sha1() helper calls (the `md5`/`sha1` npm packages, or local wrappers).
    if (/^(md5|sha1)$/i.test(funcName)) {
      algorithm = funcName.toLowerCase();
    } else if (/^(createHash|createHmac)$/i.test(funcName)) {
      // The real-world dominant shape the previous version missed entirely:
      //   crypto.createHash('md5')  /  crypto.createHmac('sha1', key)
      // Read the algorithm from the first string-literal argument.
      const first = node.arguments[0];
      if (first && (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first))) {
        if (/^(md5|sha1)$/i.test(first.text)) {
          algorithm = first.text.toLowerCase();
          viaHmac = /^createHmac$/i.test(funcName);
        }
      }
    }

    if (!algorithm) return;

    const sourceText = node.getText(this.sourceFile);
    // HMAC with a broken hash is always a security use; otherwise gate severity on whether the
    // surrounding code signals a security purpose. A plain `md5` used as a cache/etag key is
    // common and benign, so it reports at MEDIUM (hidden by the default HIGH floor) rather than
    // flooding noise — while password/signature/token contexts surface at HIGH.
    const securityContext =
      viaHmac || /password|secret|sign|token|hmac|integrity|auth|credential|session|cookie|csrf/i.test(sourceText);
    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      ruleId: 'BCR-CRYPTO-001',
      file: this.filePath,
      line: lineNum,
      column: 0,
      severity: securityContext ? 'HIGH' : 'MEDIUM',
      category: 'CRYPTO_WEAKNESS',
      title: `Weak hashing algorithm: ${algorithm.toUpperCase()}`,
      description: `${algorithm.toUpperCase()} is cryptographically broken (collisions / length-extension). Unsafe for password storage, signatures, HMAC, token derivation, or integrity checks.`,
      code: sourceText,
      recommendation: 'Use bcrypt/scrypt/argon2 for passwords and SHA-256 or stronger for integrity/signatures.',
    });
  }

  private checkPredictableTokens(node: ts.CallExpression): void {
    // Fire ONLY on the actual `Math.random()` call, not on every wrapping call
    // (`Math.random().toString(36)`, `.slice(2)`, etc.) — otherwise one source line
    // emits 3-4 duplicate findings.
    const callee = node.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const receiver = ts.isIdentifier(callee.expression) ? callee.expression.text : '';
    if (receiver !== 'Math' || callee.name.text !== 'random') return;

    const sourceText = node.getText(this.sourceFile);
    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    // The enclosing-identifier name drives the rule's specificity. We walk a few
    // levels of ancestors to find the variable / property the Math.random output
    // flows into. This catches both `const token = Math.random()...` and
    // `const sessionId = Math.random().toString(36).slice(2)`.
    const contextName = this.getNearbyIdentifierName(node) ?? '';

    if (/token/i.test(contextName)) {
      this.findings.push({
        ruleId: 'BCR-CRYPTO-002',
        file: this.filePath, line: lineNum, column: 0, severity: 'CRITICAL',
        category: 'CRYPTO_WEAKNESS',
        title: 'Predictable token with Math.random()',
        description: `Math.random() output assigned to '${contextName}' — not cryptographically secure.`,
        code: sourceText,
        recommendation: 'Use crypto.randomBytes()'
      });
      return;
    }

    if (/(session|sessionid|nonce|reset(code|token)?|otp|csrf|recovery|invitation|invite|share|magiclink|verif(y|ication)?code|resetcode|tempkey)/i.test(contextName)) {
      this.findings.push({
        ruleId: 'BCR-CRYPTO-004',
        file: this.filePath, line: lineNum, column: 0, severity: 'HIGH',
        category: 'CRYPTO_WEAKNESS',
        title: 'Identifier or Session Token Generated With Math.random()',
        description: `Math.random() output assigned to '${contextName}' — not cryptographically secure.`,
        code: sourceText,
        recommendation: 'Use crypto.randomBytes() or crypto.randomUUID().',
      });
    }
  }

  /**
   * Walks up from a CallExpression to find the binding name it flows into.
   * Returns the variable/property name or null if no such context exists.
   */
  private getNearbyIdentifierName(node: ts.Node): string | null {
    let current: ts.Node | undefined = node.parent;
    let depth = 0;
    while (current && depth < 6) {
      if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
        return current.name.text;
      }
      if (ts.isPropertyAssignment(current) && (ts.isIdentifier(current.name) || ts.isStringLiteral(current.name))) {
        return current.name.text;
      }
      if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = current.left;
        if (ts.isIdentifier(left)) return left.text;
        if (ts.isPropertyAccessExpression(left)) return left.name.text;
      }
      current = current.parent;
      depth += 1;
    }
    return null;
  }

  private checkHardcodedKeys(node: ts.CallExpression): void {
    const sourceText = node.getText(this.sourceFile);
    if (/(key|secret)\s*[:=]\s*['"][A-Za-z0-9]{10,}['"]/.test(sourceText)) {
      const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      this.findings.push({
        ruleId: 'BCR-CRYPTO-003',
        file: this.filePath, line: lineNum, column: 0, severity: 'CRITICAL',
        category: 'CRYPTO_WEAKNESS',
        title: 'Hardcoded cryptographic key',
        description: 'Keys exposed in source',
        code: sourceText,
        recommendation: 'Use environment variables'
      });
    }
  }

  private getCallExpressionName(node: ts.CallExpression): string {
    if (ts.isIdentifier(node.expression)) return node.expression.text;
    if (ts.isPropertyAccessExpression(node.expression)) return node.expression.name.text;
    return '';
  }

  getPocs(): ProofOfConcept[] {
    return this.generatedPocs;
  }
}
