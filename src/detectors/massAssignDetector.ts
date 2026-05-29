import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { MassAssignmentPocGenerator } from '../poc/templates/MassAssignmentPocGenerator';
import { PocGenerationRequest, PocGeneratorConfig } from '../poc/types';
import { Logger } from '../utils/logger';

export class MassAssignmentDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private pocGenerator: MassAssignmentPocGenerator;

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
    this.pocGenerator = new MassAssignmentPocGenerator();
  }

  detect(): DetectorResult {
    this.findings = [];

    this.detectDirectObjectAssign();
    this.detectUnvalidatedFieldAssignment();
    this.detectMissingFieldWhitelisting();
    this.detectPrototypePollution();
    this.detectConstructorInjection();
    this.detectMassAssignViaServiceCall();

    return { findings: this.findings };
  }

  /**
   * BCR-MA-006: `service.createUser(req.body)` / `Model.create(req.body)` shaped calls.
   * This is the most idiomatic mass-assignment shape in real-world backends — far more
   * common than `Object.assign(target, req.body)` — and was previously missed entirely.
   *
   * Precision controls (kept FP-low):
   *   - The callee method name must look like a mutation (`create*`/`update*`/`save*`/`insert*`/`upsert*`/`register*`).
   *   - The argument must be raw `req.body` / `request.body` / `ctx.request.body`
   *     (NOT a destructured/picked alias, NOT a validated alias).
   *   - The enclosing function must NOT show a validator (zod/joi/ajv/etc.) operating
   *     on the request body — that's the actual exit criterion.
   */
  private detectMassAssignViaServiceCall(): void {
    const allCalls = ASTVisitor.findCallExpressions(this.sourceFile);
    allCalls.forEach((call) => {
      const callee = call.expression;
      if (!ts.isPropertyAccessExpression(callee)) return;

      const methodName = callee.name.text;
      if (!/^(create|update|save|insert|upsert|register|new)([A-Z]|$)/.test(methodName)) {
        return;
      }

      // Receiver must look like a service / model / repository — not bare globals.
      const receiverName = ts.isIdentifier(callee.expression)
        ? callee.expression.text
        : callee.expression.getText(this.sourceFile);
      if (!/(service|repo|repository|model|dao|store|client|controller|resource|entity)$/i.test(receiverName) && !/^[A-Z][A-Za-z]*$/.test(receiverName.split('.').pop() ?? '')) {
        return;
      }

      // Find any argument that IS req.body / request.body / ctx.request.body.
      const rawBodyArg = call.arguments.find((arg) => {
        const text = arg.getText(this.sourceFile);
        return /^(req|request)\.body$|^ctx\.request\.body$/.test(text.trim());
      });
      if (!rawBodyArg) return;

      // If the enclosing function shows a validator, the body was likely sanitized.
      const enclosing = this.getEnclosingFunctionText(call);
      if (/\b(joi|yup|zod|valibot|ajv|class-?validator|express[-_]?validator|safe[-_]?parse|sanitize)\b/i.test(enclosing)) {
        return;
      }
      // Or explicit destructure: `const { allowed } = req.body; service.create({ allowed })`.
      if (/const\s*\{[^}]+\}\s*=\s*(req|request)\.body/.test(enclosing)) return;
      if (/\b(pick|omit|extract)\s*\(/i.test(enclosing)) return;

      const { line, column } = this.parser.getLineAndColumn(call.getStart());
      this.findings.push({
        ruleId: 'BCR-MA-006',
        category: 'MASS_ASSIGNMENT',
        severity: 'HIGH',
        title: 'Mass Assignment via Service Call With req.body',
        description: `\`${receiverName}.${methodName}\` receives raw request body without a visible schema validation in the enclosing scope. Attacker-controlled fields like role/isAdmin/verified will flow into the model.`,
        file: this.filePath,
        line,
        column,
        code: call.getText().substring(0, 140),
        recommendation: 'Validate the body through joi/zod/class-validator or pick allowed fields explicitly before passing to the service call.',
      });
    });
  }

  private getEnclosingFunctionText(node: ts.Node): string {
    let current: ts.Node | undefined = node;
    while (current) {
      if (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current)
      ) {
        return current.getText(this.sourceFile);
      }
      current = current.parent;
    }
    return node.getText(this.sourceFile);
  }

  private detectDirectObjectAssign(): void {
    const assignCalls = ASTVisitor.findCallExpressions(
      this.sourceFile,
      'Object.assign'
    );

    assignCalls.forEach((call) => {
      if (call.arguments.length >= 2) {
        const sourceArg = call.arguments[1];
        const sourceText = sourceArg.getText();

        if (
          sourceText.includes('req.body') ||
          sourceText.includes('req.query') ||
          sourceText.includes('req.params') ||
          sourceText.includes('input') ||
          sourceText.includes('data')
        ) {
          const { line, column } = this.parser.getLineAndColumn(call.getStart());
          const finding: Finding = {
            ruleId: 'BCR-MA-001',
            category: 'MASS_ASSIGNMENT',
            severity: 'CRITICAL',
            title: 'Direct Object.assign with User Input',
            description: 'Object.assign is used with unvalidated user input, risking mass assignment attacks.',
            file: this.filePath,
            line,
            column,
            code: call.getText().substring(0, 60),
            recommendation: 'Use explicit field assignment or whitelist allowed properties before assigning.',
          };

          // Generate POC
          const pocResult = this.generatePoc(call.getText(), finding, line);
          if (pocResult) {
            finding.poc = pocResult;
          }

          this.findings.push(finding);
        }
      }
    });
  }

  private detectUnvalidatedFieldAssignment(): void {
    const binaryExpressions = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    );

    binaryExpressions.forEach((node) => {
      const binExpr = node as ts.BinaryExpression;
      const leftText = binExpr.left.getText();
      const rightText = binExpr.right.getText();

      if (
        (leftText.includes('user.') || leftText.includes('obj.')) &&
        (rightText.includes('req.body') ||
          rightText.includes('req.query') ||
          rightText.includes('input'))
      ) {
        const { line, column } = this.parser.getLineAndColumn(binExpr.getStart());
        const finding: Finding = {
          ruleId: 'BCR-MA-002',
          category: 'MASS_ASSIGNMENT',
          severity: 'HIGH',
          title: 'Unvalidated Field Assignment',
          description: 'Object property directly assigned from user input without validation.',
          file: this.filePath,
          line,
          column,
          code: binExpr.getText().substring(0, 60),
          recommendation: 'Validate field names and values before assignment. Use a whitelist approach.',
        };

        // Generate POC
        const pocResult = this.generatePoc(binExpr.getText(), finding, line);
        if (pocResult) {
          finding.poc = pocResult;
        }

        this.findings.push(finding);
      }
    });
  }

  private detectMissingFieldWhitelisting(): void {
    const functionDeclarations = ASTVisitor.findFunctionDeclarations(this.sourceFile);

    functionDeclarations.forEach((func) => {
      const funcText = func.getText();

      const hasDirectAssignment =
        funcText.includes('Object.assign') ||
        funcText.includes('Object.entries') ||
        funcText.includes('spread operator') ||
        funcText.includes('...object');

      const hasWhitelist =
        funcText.includes('whitelist') ||
        funcText.includes('allowed') ||
        funcText.includes('permitted') ||
        funcText.includes('blacklist');

      if (hasDirectAssignment && !hasWhitelist) {
        const { line, column } = this.parser.getLineAndColumn(func.getStart());
        const finding: Finding = {
          ruleId: 'BCR-MA-003',
          category: 'MASS_ASSIGNMENT',
          severity: 'MEDIUM',
          title: 'Missing Field Whitelisting',
          description: `Function '${func.name?.text}' assigns object properties without field whitelisting.`,
          file: this.filePath,
          line,
          column,
          code: func.getText().substring(0, 60),
          recommendation: 'Implement field whitelisting to explicitly define which properties can be assigned.',
        };

        // Generate POC
        const pocResult = this.generatePoc(func.getText(), finding, line);
        if (pocResult) {
          finding.poc = pocResult;
        }

        this.findings.push(finding);
      }
    });
  }

  private detectPrototypePollution(): void {
    const propertyAssignments = ASTVisitor.findNodes(
      this.sourceFile,
      (node) =>
        ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    );

    propertyAssignments.forEach((node) => {
      const binExpr = node as ts.BinaryExpression;
      const leftText = binExpr.left.getText();

      if (
        leftText.includes('__proto__') ||
        leftText.includes('constructor.prototype') ||
        leftText.includes('Object.prototype')
      ) {
        const { line, column } = this.parser.getLineAndColumn(binExpr.getStart());
        const finding: Finding = {
          ruleId: 'BCR-MA-004',
          category: 'MASS_ASSIGNMENT',
          severity: 'CRITICAL',
          title: 'Prototype Pollution Vulnerability',
          description: 'Direct assignment to __proto__ or prototype can lead to prototype pollution.',
          file: this.filePath,
          line,
          column,
          code: binExpr.getText(),
          recommendation: 'Never allow assignment to __proto__ or prototype properties. Use Object.create(null) or validate deeply.',
        };

        // Generate POC
        const pocResult = this.generatePoc(binExpr.getText(), finding, line);
        if (pocResult) {
          finding.poc = pocResult;
        }

        this.findings.push(finding);
      }
    });
  }

  private detectConstructorInjection(): void {
    const objectLiterals = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isObjectLiteralExpression(node)
    );

    objectLiterals.forEach((node) => {
      const objLiteral = node as ts.ObjectLiteralExpression;
      const propMap = ASTVisitor.getObjectProperties(objLiteral);

      propMap.forEach((_value, key) => {
        if (
          key === 'constructor' ||
          key === '__proto__' ||
          key === 'prototype'
        ) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            ruleId: 'BCR-MA-005',
            category: 'MASS_ASSIGNMENT',
            severity: 'CRITICAL',
            title: 'Constructor/Prototype Property Assignment',
            description: 'Object contains constructor or prototype properties that can be exploited.',
            file: this.filePath,
            line,
            column,
            code: node.getText().substring(0, 60),
            recommendation: 'Avoid assigning to constructor, prototype, or __proto__ properties.',
          };

          // Generate POC
          const pocResult = this.generatePoc(node.getText(), finding, line);
          if (pocResult) {
            finding.poc = pocResult;
          }

          this.findings.push(finding);
        }
      });
    });
  }

  /**
   * Generate POC for mass assignment finding
   */
  private generatePoc(vulnerableCode: string, finding: Finding, line: number) {
    try {
      const config: PocGeneratorConfig = {
        includeCodeSnippets: true,
        includePayloads: true,
        includeCodeFlow: true,
        includeRemediation: true,
        verbosity: 'normal',
        format: 'markdown',
        generateDiagrams: true,
      };

      const request: PocGenerationRequest = {
        finding: finding,
        vulnerableCode: vulnerableCode,
        location: {
          file: this.filePath,
          line: line,
        },
        config: config,
      };

      const result = this.pocGenerator.generate(request);
      return result.success ? result.poc : null;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error('Failed to generate POC for mass assignment finding', {
        error: errorMessage,
        line,
      });
      return null;
    }
  }
}
