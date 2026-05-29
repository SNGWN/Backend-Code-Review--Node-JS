import * as ts from 'typescript';
import { DetectorResult, Finding } from '../types';
import { ASTParser } from '../parser/astParser';
import { ASTVisitor } from '../parser/astVisitor';

/**
 * Security misconfiguration detector.
 *
 * Covers the high-frequency gaps identified by the real-world audit:
 *   - BCR-MISC-001: `cors({ origin: '*' })` / `cors()` default-wildcard
 *   - BCR-MISC-002: `express.json()` / `urlencoded()` / `bodyParser.json()` with no `limit`
 *   - BCR-MISC-003: `helmet()` with no options (default-only)
 *   - BCR-MISC-004: `bcrypt.hash(...)` / `bcrypt.genSalt(N)` with low cost factor
 *   - BCR-CRYPTO-005: deprecated `crypto.createCipher` / `createDecipher` (no IV)
 *
 * Each rule is high-signal because we anchor on the exact call shape (receiver + method
 * + literal arg structure), not text substring.
 */
export class MisconfigurationDetector {
  private findings: Finding[] = [];

  constructor(
    private filePath: string,
    private sourceFile: ts.SourceFile,
    private parser: ASTParser
  ) {}

  detect(): DetectorResult {
    this.findings = [];

    ASTVisitor.findCallExpressions(this.sourceFile).forEach((call) => {
      this.checkCorsWildcard(call);
      this.checkBodyParserLimit(call);
      this.checkHelmetDefaults(call);
      this.checkBcryptCost(call);
      this.checkDeprecatedCipher(call);
    });

    return { findings: this.findings };
  }

  // ── BCR-MISC-001 ─────────────────────────────────────────────────────────
  private checkCorsWildcard(call: ts.CallExpression): void {
    const callee = call.expression;
    if (!this.calleeIs(callee, 'cors')) return;

    // bare cors() → permissive (default reflects any origin in older versions, allows
    // all in newer); cors({ origin: '*' | true }) → explicit wildcard.
    let isWildcard = call.arguments.length === 0;
    if (!isWildcard && call.arguments.length === 1) {
      const arg = call.arguments[0];
      if (ts.isObjectLiteralExpression(arg)) {
        for (const prop of arg.properties) {
          if (!ts.isPropertyAssignment(prop)) continue;
          const name = ts.isIdentifier(prop.name) ? prop.name.text : ts.isStringLiteral(prop.name) ? prop.name.text : '';
          if (name !== 'origin') continue;
          const value = prop.initializer;
          if (ts.isStringLiteral(value) && value.text === '*') isWildcard = true;
          else if (value.kind === ts.SyntaxKind.TrueKeyword) isWildcard = true;
        }
      }
    }
    if (!isWildcard) return;

    this.emit(call, {
      ruleId: 'BCR-MISC-001',
      severity: 'HIGH',
      category: 'MISCONFIGURATION',
      title: 'Permissive CORS Configuration',
      description: 'CORS middleware accepts any origin, enabling cross-origin reads of authenticated responses.',
      recommendation: 'Configure CORS with an explicit allowlist of origins. Never use `origin: "*"` on routes that require credentials.',
    });
  }

  // ── BCR-MISC-002 ─────────────────────────────────────────────────────────
  private checkBodyParserLimit(call: ts.CallExpression): void {
    const callee = call.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const method = callee.name.text;
    if (method !== 'json' && method !== 'urlencoded' && method !== 'raw' && method !== 'text') return;

    const receiverName = ts.isIdentifier(callee.expression) ? callee.expression.text : '';
    if (!/^(express|bodyParser|body_parser|app)$/i.test(receiverName)) return;

    // If `limit` is set, we're done.
    const arg = call.arguments[0];
    if (arg && ts.isObjectLiteralExpression(arg)) {
      const hasLimit = arg.properties.some((prop) => {
        if (!ts.isPropertyAssignment(prop)) return false;
        return ts.isIdentifier(prop.name) && prop.name.text === 'limit';
      });
      if (hasLimit) return;
    }

    this.emit(call, {
      ruleId: 'BCR-MISC-002',
      severity: 'MEDIUM',
      category: 'MISCONFIGURATION',
      title: 'Body Parser Without Size Limit',
      description: `\`${receiverName}.${method}()\` is configured without an explicit \`limit\`. The default 100kb allows DoS via large payloads on permissive endpoints.`,
      recommendation: `Set an explicit limit: \`${receiverName}.${method}({ limit: "100kb" })\`.`,
    });
  }

  // ── BCR-MISC-003 ─────────────────────────────────────────────────────────
  private checkHelmetDefaults(call: ts.CallExpression): void {
    const callee = call.expression;
    if (!this.calleeIs(callee, 'helmet')) return;
    // helmet() with no args → defaults only. helmet({...}) → explicit choice.
    if (call.arguments.length > 0) return;

    this.emit(call, {
      ruleId: 'BCR-MISC-003',
      severity: 'LOW',
      category: 'MISCONFIGURATION',
      title: 'Helmet Configured Without Options',
      description: 'helmet() is registered with no options, accepting all defaults. Modern apps should explicitly choose CSP/HSTS that matches their domain.',
      recommendation: 'Pass an explicit options object: `helmet({ contentSecurityPolicy: {...}, hsts: { maxAge: ... } })`.',
    });
  }

  // ── BCR-MISC-004 ─────────────────────────────────────────────────────────
  private checkBcryptCost(call: ts.CallExpression): void {
    const callee = call.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const receiverName = ts.isIdentifier(callee.expression) ? callee.expression.text : '';
    if (!/^(bcrypt|bcryptjs)$/i.test(receiverName)) return;

    const method = callee.name.text;
    let costArg: ts.Expression | undefined;
    if (method === 'hash' || method === 'hashSync') {
      costArg = call.arguments[1];
    } else if (method === 'genSalt' || method === 'genSaltSync') {
      costArg = call.arguments[0];
    }
    if (!costArg) return;

    const numeric = this.readNumericLiteral(costArg);
    if (numeric === undefined || numeric >= 10) return;

    this.emit(call, {
      ruleId: 'BCR-MISC-004',
      severity: 'HIGH',
      category: 'MISCONFIGURATION',
      title: 'Weak bcrypt Cost Factor',
      description: `bcrypt.${method} is called with cost ${numeric}. Modern hardware brute-forces low-cost hashes quickly; current OWASP guidance is ≥ 10 (12 preferred).`,
      recommendation: `Increase the bcrypt cost factor to at least 10 (12 recommended): \`${receiverName}.${method}(password, 12)\`.`,
    });
  }

  // ── BCR-CRYPTO-005 ───────────────────────────────────────────────────────
  private checkDeprecatedCipher(call: ts.CallExpression): void {
    const callee = call.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const receiverName = ts.isIdentifier(callee.expression) ? callee.expression.text : '';
    if (receiverName !== 'crypto') return;
    const method = callee.name.text;
    if (method !== 'createCipher' && method !== 'createDecipher') return;

    this.emit(call, {
      ruleId: 'BCR-CRYPTO-005',
      severity: 'CRITICAL',
      category: 'CRYPTO_WEAKNESS',
      title: 'Deprecated crypto.createCipher (IV-less)',
      description: `\`crypto.${method}\` derives the IV from the key and is deprecated. Use \`${method === 'createCipher' ? 'createCipheriv' : 'createDecipheriv'}\` with a unique random IV.`,
      recommendation: `Use crypto.${method === 'createCipher' ? 'createCipheriv' : 'createDecipheriv'}(algorithm, key, crypto.randomBytes(16)).`,
    });
  }

  private calleeIs(expr: ts.LeftHandSideExpression, name: string): boolean {
    return ts.isIdentifier(expr) && expr.text === name;
  }

  private readNumericLiteral(node: ts.Expression): number | undefined {
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (ts.isPrefixUnaryExpression(node) && ts.isNumericLiteral(node.operand)) {
      const value = Number(node.operand.text);
      return node.operator === ts.SyntaxKind.MinusToken ? -value : value;
    }
    return undefined;
  }

  private emit(
    call: ts.CallExpression,
    shape: { ruleId: string; severity: Finding['severity']; category: Finding['category']; title: string; description: string; recommendation: string }
  ): void {
    const { line, column } = this.parser.getLineAndColumn(call.getStart());
    this.findings.push({
      ruleId: shape.ruleId,
      category: shape.category,
      severity: shape.severity,
      title: shape.title,
      description: shape.description,
      file: this.filePath,
      line,
      column,
      code: call.getText().substring(0, 140),
      recommendation: shape.recommendation,
    });
  }
}
