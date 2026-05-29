import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';

export class DataExposureDetector {
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
      if (ts.isReturnStatement(node) || ts.isObjectLiteralExpression(node)) {
        this.checkUnfilteredResponses(node);
        this.checkSensitiveFieldExposure(node);
      }
    });
    return { findings: this.findings };
  }

  private checkUnfilteredResponses(node: ts.Node): void {
    // Tightened: require the node to actually be a res.json/res.send/return-of-user
    // call AND for the EXPLICIT field pattern (`.password,` etc.) to appear. The
    // previous version fired on any node text containing the *word* "password" —
    // including innocuous strings like `res.json({ message: 'password updated' })`.
    if (!ts.isCallExpression(node) && !ts.isReturnStatement(node)) {
      return;
    }
    const sourceText = node.getText(this.sourceFile);
    if (!/res\.send\(|res\.json\(|\breturn\s+.*\buser\b/.test(sourceText)) {
      return;
    }
    if (!/\.(password|token|secret|apiKey|creditCard|ssn)\s*[,}]/.test(sourceText)) {
      return;
    }
    if (/delete\s+\w+\.(password|token|secret|apiKey|creditCard|ssn)|\.\.\.rest|omit\(|pick\(/.test(sourceText)) {
      return;
    }
    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      ruleId: 'BCR-DE-001',
      file: this.filePath,
      line: lineNum,
      column: 0,
      severity: 'HIGH',
      category: 'DATA_EXPOSURE',
      title: 'Unfiltered sensitive data in API response',
      description: 'User objects contain passwords, tokens, or other sensitive fields that should be excluded',
      code: sourceText,
      recommendation: 'Filter sensitive fields before returning: const { password, ...safeUser } = user;',
    });
  }

  private checkSensitiveFieldExposure(node: ts.Node): void {
    const sourceText = node.getText(this.sourceFile);

    const sensitivePatterns = [
      { field: 'password', pattern: /\.password\s*[,}]/ },
      { field: 'apiKey', pattern: /\.apiKey\s*[,}]/ },
      { field: 'secret', pattern: /\.secret\s*[,}]/ },
      { field: 'creditCard', pattern: /\.creditCard\s*[,}]/ },
      { field: 'ssn', pattern: /\.ssn\s*[,}]/ },
      { field: 'token', pattern: /\.token\s*[,}]/ }
    ];

    // Tightened HTTP-response gate. Previously `send|json|return|response` matched
    // `return bcrypt.compare(password, user.password, …)` because of the word "return".
    // We now require either an actual response-sink method call, or that the enclosing
    // function name clearly signals response/DTO construction (e.g. `buildXResponse`,
    // `toUserDto`, `serializeUser`).
    const RESPONSE_SINK = /(\bres|\bresponse|\breply|\bctx\.body|\bctx\.response)\.(send|json|status|end|render|attachment|download)\s*\(/i;
    const inResponseBuilder = this.isInsideResponseBuilderFunction(node);
    for (const { field, pattern } of sensitivePatterns) {
      if (!pattern.test(sourceText)) continue;
      if (!RESPONSE_SINK.test(sourceText) && !inResponseBuilder) continue;

      const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      this.findings.push({
        ruleId: 'BCR-DE-002',
        file: this.filePath,
        line: lineNum,
        column: 0,
        severity: 'HIGH',
        category: 'DATA_EXPOSURE',
        title: `Sensitive field "${field}" exposed in response`,
        description: `The "${field}" field should not be exposed in API responses`,
        code: sourceText,
        recommendation: `Exclude "${field}" field: const safeUser = { ...user }; delete safeUser.${field};`,
      });
    }
  }

  /**
   * Walk up to the enclosing function declaration / expression and check whether its
   * name reads like a response/DTO builder. These functions construct payloads that
   * downstream handlers send back to the client, so direct sensitive-field exposure
   * here is still a leak even without a literal `res.json(...)` in scope.
   */
  private isInsideResponseBuilderFunction(node: ts.Node): boolean {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      let name: string | undefined;
      if (ts.isFunctionDeclaration(current) && current.name) {
        name = current.name.text;
      } else if (ts.isMethodDeclaration(current) && ts.isIdentifier(current.name)) {
        name = current.name.text;
      } else if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
        name = current.name.text;
      }
      if (name && /(response|dto|payload|serialize|present|view|render|toJson|toJSON)$/i.test(name)) {
        return true;
      }
      if (name && /^(build|make|create|format|to)\w*(response|dto|payload|view|json)/i.test(name)) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  getPocs(): ProofOfConcept[] {
    return this.generatedPocs;
  }
}
