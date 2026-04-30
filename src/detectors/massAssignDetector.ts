import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { MassAssignmentPocGenerator } from '../poc/templates/MassAssignmentPocGenerator';
import { PocGenerationRequest, PocGeneratorConfig } from '../poc/types';

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

    return { findings: this.findings };
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

      propMap.forEach((value, key) => {
        if (
          key === 'constructor' ||
          key === '__proto__' ||
          key === 'prototype'
        ) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
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
      console.error(`Failed to generate POC for mass assignment finding: ${errorMessage}`);
      return null;
    }
  }
}
