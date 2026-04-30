import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';

const POC_CONFIG = {
  includeCodeSnippets: true,
  includePayloads: true,
  includeCodeFlow: true,
  includeRemediation: true,
  verbosity: 'detailed' as const,
  format: 'markdown' as const,
  generateDiagrams: true
};

export class CryptoWeaknessDetector {
  private findings: Finding[] = [];
  private generatedPocs: ProofOfConcept[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
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
    const sourceText = node.getText(this.sourceFile);
    if (/Math\.random/.test(sourceText) && /token/i.test(sourceText)) {
      const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      this.findings.push({
        file: this.filePath, line: lineNum, column: 0, severity: 'CRITICAL',
        category: 'CRYPTO_WEAKNESS',
        title: 'Predictable token with Math.random()',
        description: 'Not cryptographically secure',
        code: sourceText,
        recommendation: 'Use crypto.randomBytes()'
      });
    }
  }

  private checkHardcodedKeys(node: ts.CallExpression): void {
    const sourceText = node.getText(this.sourceFile);
    if (/(key|secret)\s*[:=]\s*['"][A-Za-z0-9]{10,}['"]/.test(sourceText)) {
      const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      this.findings.push({
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
