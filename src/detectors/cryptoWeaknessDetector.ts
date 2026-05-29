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
    });
    return { findings: this.findings };
  }

  private checkWeakHashing(node: ts.CallExpression): void {
    const funcName = this.getCallExpressionName(node);
    if (/^(md5|sha1)$/i.test(funcName)) {
      const sourceText = node.getText(this.sourceFile);
      if (/password|secret/i.test(sourceText)) {
        const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        this.findings.push({
          ruleId: 'BCR-CRYPTO-001',
          file: this.filePath, line: lineNum, column: 0, severity: 'HIGH',
          category: 'CRYPTO_WEAKNESS',
          title: `Weak hashing: ${funcName}`,
          description: 'MD5/SHA1 broken for passwords',
          code: sourceText,
          recommendation: 'Use bcrypt'
        });
      }
    }
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
