import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept, PocGenerationRequest } from '../poc/types';
import { Logger } from '../utils/logger';
import { hasValidationBoundary, isUntrustedInputText } from '../utils/detectorLogic';

/**
 * Insecure Deserialization Detector
 *
 * Detects deserialization vulnerabilities in TypeScript backend code:
 * - Unsafe JSON.parse with user input (RCE via __proto__)
 * - Using eval() to deserialize (code injection)
 * - Unsafe Object.assign/spread with untrusted data
 * - Prototype pollution (__proto__, constructor.prototype)
 * - Gadget chain usage patterns
 * - Missing input validation before deserialization
 *
 * @example
 * const detector = new DeserializationDetector('api.ts', sourceFile, parser);
 * const result = detector.detect();
 * result.findings; // Array of deserialization issues
 */
export class DeserializationDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private untrustedVariables = new Set<string>();

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  /**
   * Detects all deserialization vulnerabilities in the source file
   *
   * @returns DetectorResult containing array of deserialization findings
   */
  detect(): DetectorResult {
    this.findings = [];
    this.untrustedVariables.clear();

    this.buildUntrustedVariableMap();
    this.detectUnsafeJsonParse();
    this.detectEvalDeserialization();
    this.detectPrototypePollution();
    this.detectUnsafeObjectAssign();
    this.detectUnsafeSpreadOperator();
    this.detectGadgetChainPatterns();

    return { findings: this.findings };
  }

  /**
   * Builds a map of untrusted variables (from req.body, req.query, user input)
   *
   * @private
   */
  private buildUntrustedVariableMap(): void {
    const assignments = ASTVisitor.findNodes(this.sourceFile, (node) => {
      return ts.isVariableDeclaration(node);
    });

    assignments.forEach((node) => {
      const varDecl = node as ts.VariableDeclaration;
      if (varDecl.initializer) {
        const text = varDecl.initializer.getText();
        if (isUntrustedInputText(text) || this.referencesUntrustedAlias(varDecl.initializer)) {
          if (ts.isIdentifier(varDecl.name)) {
            this.untrustedVariables.add(varDecl.name.text);
            return;
          }

          if (ts.isObjectBindingPattern(varDecl.name)) {
            varDecl.name.elements.forEach((element) => {
              if (ts.isIdentifier(element.name)) {
                this.untrustedVariables.add(element.name.text);
              }
            });
          }
        }
      }
    });
  }

  private referencesUntrustedAlias(node: ts.Node): boolean {
    const text = node.getText();
    if (isUntrustedInputText(text)) {
      return true;
    }

    for (const variable of this.untrustedVariables) {
      const variablePattern = new RegExp(`\\b${variable}\\b`);
      if (variablePattern.test(text)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Detects unsafe JSON.parse with user input
   *
   * @private
   */
  private detectUnsafeJsonParse(): void {
    const jsonParseCalls = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        return name === 'JSON.parse' || name === 'parse';
      }
      return false;
    });

    jsonParseCalls.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      if (callExpr.arguments.length > 0) {
        const firstArg = callExpr.arguments[0];
        const argText = firstArg.getText();

        if (this.isUntrustedInput(argText) && !hasValidationBoundary(callExpr, this.sourceFile)) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            category: 'VALIDATION',
            severity: 'CRITICAL',
            title: 'Unsafe JSON.parse with User Input',
            description: 'User input is directly passed to JSON.parse without sanitization. This can lead to prototype pollution attacks via __proto__ gadgets.',
            file: this.filePath,
            line,
            column,
            code: node.getText(),
            recommendation: 'Validate JSON structure using a JSON schema validator. Use JSON.parse with a reviver function to filter out __proto__ and constructor properties.',
          };

          this.generateDeserializationPoc(finding, 'JSON_PARSE_POLLUTION');
          this.findings.push(finding);
        }
      }
    });
  }

  /**
   * Detects eval() usage for deserialization (code injection)
   *
   * @private
   */
  private detectEvalDeserialization(): void {
    const evalCalls = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        return name === 'eval' || name === 'Function';
      }
      return false;
    });

    evalCalls.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      if (callExpr.arguments.length > 0) {
        const firstArg = callExpr.arguments[0];
        const argText = firstArg.getText();

        if (this.isUntrustedInput(argText) && !hasValidationBoundary(callExpr, this.sourceFile)) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            category: 'VALIDATION',
            severity: 'CRITICAL',
            title: 'Code Injection via eval() Deserialization',
            description: 'User input is passed to eval() or Function constructor for deserialization. This allows arbitrary code execution.',
            file: this.filePath,
            line,
            column,
            code: node.getText(),
            recommendation: 'Never use eval() or Function constructor with untrusted input. Use JSON.parse for JSON data or safe serialization libraries.',
          };

          this.generateDeserializationPoc(finding, 'EVAL_INJECTION');
          this.findings.push(finding);
        }
      }
    });
  }

  /**
   * Detects prototype pollution patterns
   *
   * @private
   */
  private detectPrototypePollution(): void {
    const propertyAssignments = ASTVisitor.findNodes(this.sourceFile, (node) => {
      return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken;
    });

    propertyAssignments.forEach((node) => {
      const binExpr = node as ts.BinaryExpression;
      const leftText = binExpr.left.getText();
      const rightText = binExpr.right.getText();

      // Check for __proto__ or constructor.prototype pollution
      if ((leftText.includes('__proto__') || leftText.includes('constructor.prototype')) && 
          this.isUntrustedInput(rightText)) {
        const { line, column } = this.parser.getLineAndColumn(node.getStart());
        const finding: Finding = {
          category: 'VALIDATION',
          severity: 'CRITICAL',
          title: 'Prototype Pollution Vulnerability',
          description: 'User input is assigned to __proto__ or constructor.prototype, allowing prototype pollution attacks.',
          file: this.filePath,
          line,
          column,
          code: node.getText(),
          recommendation: 'Use Object.preventExtensions() and Object.freeze() to lock prototypes. Validate input strictly and filter __proto__ and constructor properties.',
        };

        this.generateDeserializationPoc(finding, 'PROTOTYPE_POLLUTION');
        this.findings.push(finding);
      }
    });
  }

  /**
   * Detects unsafe Object.assign with untrusted data
   *
   * @private
   */
  private detectUnsafeObjectAssign(): void {
    const objectAssignCalls = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        return name === 'Object.assign' || name === 'assign';
      }
      return false;
    });

    objectAssignCalls.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      if (callExpr.arguments.length >= 2) {
        const targetArg = callExpr.arguments[0].getText();
        
        // Check if any source argument is untrusted
        for (let i = 1; i < callExpr.arguments.length; i++) {
          const sourceArg = callExpr.arguments[i].getText();
          
          if (this.isUntrustedInput(sourceArg) && !hasValidationBoundary(callExpr, this.sourceFile)) {
            const { line, column } = this.parser.getLineAndColumn(node.getStart());
            const finding: Finding = {
              category: 'VALIDATION',
              severity: 'HIGH',
              title: 'Unsafe Object.assign with Untrusted Data',
              description: 'Object.assign is used with untrusted data as source, which can pollute the target object and overwrite critical properties.',
              file: this.filePath,
              line,
              column,
              code: node.getText(),
              recommendation: 'Validate input structure before Object.assign. Use a whitelist of allowed properties or use Object.create(null) for target objects.',
            };

            this.generateDeserializationPoc(finding, 'OBJECT_ASSIGN_POLLUTION');
            this.findings.push(finding);
            break;
          }
        }
      }
    });
  }

  /**
   * Detects unsafe spread operator with untrusted data
   *
   * @private
   */
  private detectUnsafeSpreadOperator(): void {
    const spreadElements = ASTVisitor.findNodes(this.sourceFile, (node) => {
      return ts.isSpreadAssignment(node) || ts.isSpreadElement(node);
    });

    spreadElements.forEach((node) => {
      const spreadExpr = node as ts.SpreadAssignment | ts.SpreadElement;
      const expressionText = spreadExpr.expression.getText();

        if (this.isUntrustedInput(expressionText) && !hasValidationBoundary(spreadExpr, this.sourceFile)) {
        // Check if spreading into an object
        const parent = spreadExpr.parent;
        if (parent && ts.isObjectLiteralExpression(parent)) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            category: 'VALIDATION',
            severity: 'HIGH',
            title: 'Unsafe Object Spread with Untrusted Data',
            description: 'Spread operator is used with untrusted data to merge into objects, which can lead to property pollution.',
            file: this.filePath,
            line,
            column,
            code: node.getText(),
            recommendation: 'Validate and filter input properties before spreading. Use a property whitelist to only spread allowed properties.',
          };

          this.generateDeserializationPoc(finding, 'SPREAD_POLLUTION');
          this.findings.push(finding);
        }
      }
    });
  }

  /**
   * Detects gadget chain usage patterns
   *
   * @private
   */
  private detectGadgetChainPatterns(): void {
    const gadgetPatterns = [
      /\.toJSON\s*\(/,
      /\.valueOf\s*\(/,
      /\.toString\s*\(/,
      /\.constructor\s*\(/,
      /Object\.create\s*\(/,
      /Object\.defineProperty\s*\(/,
    ];

    const allCallExpressions = ASTVisitor.findNodes(this.sourceFile, (node) => {
      return ts.isCallExpression(node);
    });

    allCallExpressions.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const text = callExpr.getText();

      // Check if any argument is untrusted and gadget pattern is used
      const args = callExpr.arguments;
      let hasUntrustedArg = false;

      args.forEach(arg => {
        if (this.isUntrustedInput(arg.getText())) {
          hasUntrustedArg = true;
        }
      });

      if (
        hasUntrustedArg &&
        !hasValidationBoundary(callExpr, this.sourceFile) &&
        gadgetPatterns.some(pattern => pattern.test(text))
      ) {
        const { line, column } = this.parser.getLineAndColumn(node.getStart());
        const finding: Finding = {
          category: 'VALIDATION',
          severity: 'HIGH',
          title: 'Potential Gadget Chain Usage',
          description: 'Code uses object methods that could be part of gadget chains with untrusted input, potentially leading to code execution.',
          file: this.filePath,
          line,
          column,
          code: node.getText(),
          recommendation: 'Avoid using untrusted data with methods that could be part of gadget chains. Use safe deserialization methods.',
        };

        this.generateDeserializationPoc(finding, 'GADGET_CHAIN');
        this.findings.push(finding);
      }
    });
  }

  /**
   * Checks if text represents untrusted input
   *
   * @param text - The text to check
   * @returns true if untrusted, false otherwise
   * @private
   */
  private isUntrustedInput(text: string): boolean {
    // Check if it's a variable that's known to be untrusted
    const tokens = text.split(/[\.\[\]]/);
    const varName = tokens[0].trim();

    if (this.untrustedVariables.has(varName)) {
      return true;
    }

    // Check for direct untrusted sources
    return isUntrustedInputText(text);
  }

  /**
   * Checks if text represents an untrusted source
   *
   * @param text - The text to check
   * @returns true if untrusted, false otherwise
   * @private
   */
  /**
   * Generates POC for deserialization vulnerability
   *
   * @param finding - The finding to generate POC for
   * @param vulnerabilityType - The type of vulnerability
   * @private
   */
  private generateDeserializationPoc(finding: Finding, vulnerabilityType: string): void {
    try {
      const request: PocGenerationRequest = {
        finding,
        vulnerableCode: finding.code,
        location: {
          file: finding.file,
          line: finding.line,
          column: finding.column,
        },
        config: {
          includeCodeSnippets: true,
          includePayloads: true,
          includeCodeFlow: true,
          includeRemediation: true,
          verbosity: 'normal',
          format: 'markdown',
          generateDiagrams: true,
        },
      };

      // const result = this.pocGenerator.generate(request, vulnerabilityType);
      //
      // if (result.success && result.poc) {
      //   finding.poc = result.poc;
      // }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.debug('Deserialization POC generation failed', { error: errorMessage, line: finding.line });
    }
  }

  /**
   * Gets all generated POCs
   *
   * @returns Array of POCs from findings
   */
  getGeneratedPocs(): ProofOfConcept[] {
    return this.findings
      .filter((f) => f.poc)
      .map((f) => f.poc as ProofOfConcept);
  }
}
