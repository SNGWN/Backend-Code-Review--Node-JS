import * as ts from 'typescript';
import { DetectorResult, Finding } from '../types';
import { ASTParser } from '../parser/astParser';
import { ASTVisitor } from '../parser/astVisitor';

/**
 * Insecure transport / TLS detector.
 *
 * Catches the two highest-frequency ways Node.js backends silently disable TLS
 * certificate validation — both reduce an HTTPS call to an unauthenticated channel,
 * exposing every outbound request (payment gateways, identity providers, internal
 * service mesh) to a man-in-the-middle:
 *
 *   - BCR-TLS-001: `rejectUnauthorized: false` in any options object. This flag is read
 *     by https.request / https.Agent / tls.connect and by every HTTP client that forwards
 *     an agent (axios, got, node-fetch, request, undici). Once false, forged/self-signed
 *     certificates are accepted without error.
 *   - BCR-TLS-002: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`. A process-global kill
 *     switch that disables certificate validation for EVERY TLS connection in the process.
 *
 * Both rules anchor on exact structure (property name + literal value / assignment target),
 * so they are high-signal with effectively no false positives.
 */
export class InsecureTransportDetector {
  private findings: Finding[] = [];

  constructor(
    private filePath: string,
    private sourceFile: ts.SourceFile,
    private parser: ASTParser
  ) {}

  detect(): DetectorResult {
    this.findings = [];

    ASTVisitor.visit(this.sourceFile, (node) => {
      if (ts.isObjectLiteralExpression(node)) {
        this.checkRejectUnauthorized(node);
      }
      if (ts.isBinaryExpression(node)) {
        this.checkGlobalTlsKillSwitch(node);
      }
    });

    return { findings: this.findings };
  }

  // ── BCR-TLS-001 ────────────────────────────────────────────────────────────
  private checkRejectUnauthorized(obj: ts.ObjectLiteralExpression): void {
    for (const prop of obj.properties) {
      if (!ts.isPropertyAssignment(prop)) continue;
      const name = this.propName(prop.name);
      if (name !== 'rejectUnauthorized') continue;
      if (prop.initializer.kind !== ts.SyntaxKind.FalseKeyword) continue;

      this.emit(prop, {
        ruleId: 'BCR-TLS-001',
        severity: 'CRITICAL',
        title: 'TLS Certificate Validation Disabled (rejectUnauthorized: false)',
        description:
          'An HTTPS/TLS options object sets `rejectUnauthorized: false`, which accepts any certificate (self-signed, expired, or attacker-forged). The connection is no longer authenticated and is open to man-in-the-middle interception of every request and response.',
        recommendation:
          'Remove `rejectUnauthorized: false`. If you must trust a private CA, pass that CA via the `ca` option instead of disabling validation. Never disable certificate checking to work around a TLS error.',
      });
    }
  }

  // ── BCR-TLS-002 ────────────────────────────────────────────────────────────
  // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'  (or "0" / 0)
  private checkGlobalTlsKillSwitch(node: ts.BinaryExpression): void {
    if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
    if (!this.isEnvTlsTarget(node.left)) return;
    if (!this.isZeroLiteral(node.right)) return;

    this.emit(node, {
      ruleId: 'BCR-TLS-002',
      severity: 'CRITICAL',
      title: 'Global TLS Verification Disabled via NODE_TLS_REJECT_UNAUTHORIZED',
      description:
        'Setting `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"` disables certificate validation for EVERY TLS connection in the process, not just one client. Any outbound HTTPS request can be silently man-in-the-middled.',
      recommendation:
        'Never set NODE_TLS_REJECT_UNAUTHORIZED to 0. Trust a specific private CA via the `ca` option on the individual client instead, and keep validation enabled everywhere else.',
    });
  }

  /** Matches `process.env.NODE_TLS_REJECT_UNAUTHORIZED` and `process.env['NODE_TLS_...']`. */
  private isEnvTlsTarget(expr: ts.Expression): boolean {
    const ENV = 'NODE_TLS_REJECT_UNAUTHORIZED';
    if (ts.isPropertyAccessExpression(expr)) {
      return expr.name.text === ENV && this.isProcessEnv(expr.expression);
    }
    if (ts.isElementAccessExpression(expr)) {
      const arg = expr.argumentExpression;
      const key = ts.isStringLiteralLike(arg) ? arg.text : '';
      return key === ENV && this.isProcessEnv(expr.expression);
    }
    return false;
  }

  private isProcessEnv(expr: ts.Expression): boolean {
    return (
      ts.isPropertyAccessExpression(expr) &&
      expr.name.text === 'env' &&
      ts.isIdentifier(expr.expression) &&
      expr.expression.text === 'process'
    );
  }

  private isZeroLiteral(expr: ts.Expression): boolean {
    if (ts.isStringLiteralLike(expr)) return expr.text.trim() === '0';
    if (ts.isNumericLiteral(expr)) return expr.text === '0';
    return false;
  }

  private propName(name: ts.PropertyName): string {
    if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
    return '';
  }

  private emit(
    node: ts.Node,
    shape: { ruleId: string; severity: Finding['severity']; title: string; description: string; recommendation: string }
  ): void {
    const { line, column } = this.parser.getLineAndColumn(node.getStart());
    this.findings.push({
      ruleId: shape.ruleId,
      category: 'MISCONFIGURATION',
      severity: shape.severity,
      title: shape.title,
      description: shape.description,
      file: this.filePath,
      line,
      column,
      code: node.getText().substring(0, 140),
      recommendation: shape.recommendation,
    });
  }
}
