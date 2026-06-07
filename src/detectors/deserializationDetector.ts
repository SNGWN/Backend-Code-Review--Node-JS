import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';
import { Logger } from '../utils/logger';
import { hasValidationBoundary, isUntrustedInputText } from '../utils/detectorLogic';
import { TaintTracker } from '../utils/taint';

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
  private taintTracker: TaintTracker | null = null;

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
    this.taintTracker = new TaintTracker(this.sourceFile);

    this.buildUntrustedVariableMap();
    this.detectUnsafeJsonParse();
    this.detectEvalDeserialization();
    this.detectPrototypePollution();
    this.detectUnsafeObjectAssign();
    this.detectUnsafeSpreadOperator();
    this.detectGadgetChainPatterns();
    this.detectBase64Deserialization();

    return { findings: this.findings };
  }

  /**
   * BCR-VAL-012: `Buffer.from(x, 'base64').toString(...)` where `x` is user-controlled.
   * Common in poorly-implemented Basic auth and webhook signature verification; the
   * decoded string typically flows into JSON.parse or credential splitting.
   */
  private detectBase64Deserialization(): void {
    ASTVisitor.findNodes(this.sourceFile, (node) => ts.isCallExpression(node)).forEach((node) => {
      const call = node as ts.CallExpression;
      const callee = call.expression;
      if (!ts.isPropertyAccessExpression(callee)) return;
      if (callee.name.text !== 'from') return;
      if (!ts.isIdentifier(callee.expression) || callee.expression.text !== 'Buffer') return;
      // Second argument must be the literal 'base64'.
      const second = call.arguments[1];
      if (!second || !ts.isStringLiteral(second) || second.text.toLowerCase() !== 'base64') return;

      const first = call.arguments[0];
      if (!first) return;
      if (!this.referencesUntrustedAlias(first)) return;

      // Only fire when the result is consumed by `.toString(...)` — that's the
      // deserialization step that exposes the application to attacker-controlled bytes.
      const parent = call.parent;
      if (!parent || !ts.isPropertyAccessExpression(parent) || parent.name.text !== 'toString') return;

      const { line, column } = this.parser.getLineAndColumn(node.getStart());
      this.findings.push({
        ruleId: 'BCR-VAL-012',
        category: 'VALIDATION',
        severity: 'HIGH',
        title: 'Insecure Deserialization From Base64',
        description: 'Buffer.from(<user>, "base64").toString(...) decodes attacker-controlled base64 and exposes downstream parsing to malformed bytes.',
        file: this.filePath,
        line,
        column,
        code: node.getText().substring(0, 140),
        recommendation: 'Validate the decoded payload against a strict schema. For Basic auth use `basic-auth`; for webhook signatures verify HMAC BEFORE decoding.',
      });
    });
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
    // Use scope-aware tracker — replaces the prior `\b${variable}\b` regex that collided
    // on common identifier names ("data", "input", "result").
    if (this.taintTracker?.isTainted(node)) {
      return true;
    }
    return isUntrustedInputText(node.getText());
  }

  /**
   * Detects unsafe JSON.parse with user input
   *
   * @private
   */
  private detectUnsafeJsonParse(): void {
    const jsonParseCalls = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (!ts.isCallExpression(node)) return false;
      const expr = node.expression;
      if (!ts.isPropertyAccessExpression(expr)) return false;
      const objectName = ts.isIdentifier(expr.expression) ? expr.expression.text : '';
      // Strict: only JSON.parse, not arbitrary `.parse()` (which matches z.parse(), parser.parse(), etc.).
      return objectName === 'JSON' && expr.name.text === 'parse';
    });

    jsonParseCalls.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      if (callExpr.arguments.length === 0) return;
      const firstArg = callExpr.arguments[0];

      if (this.referencesUntrustedAlias(firstArg) && !hasValidationBoundary(callExpr, this.sourceFile)) {
        const { line, column } = this.parser.getLineAndColumn(node.getStart());
        const finding: Finding = {
          ruleId: 'BCR-VAL-005',
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

        if (this.referencesUntrustedAlias(firstArg) && !hasValidationBoundary(callExpr, this.sourceFile)) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            ruleId: 'BCR-VAL-006',
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
          (this.isUntrustedInput(rightText) || this.referencesUntrustedAlias(binExpr.right))) {
        const { line, column } = this.parser.getLineAndColumn(node.getStart());
        const finding: Finding = {
          ruleId: 'BCR-VAL-007',
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
        // Check if any source argument is untrusted
        for (let i = 1; i < callExpr.arguments.length; i++) {
          const sourceArgNode = callExpr.arguments[i];

          if (this.referencesUntrustedAlias(sourceArgNode) && !hasValidationBoundary(callExpr, this.sourceFile)) {
            const { line, column } = this.parser.getLineAndColumn(node.getStart());
            const finding: Finding = {
              ruleId: 'BCR-VAL-008',
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

      if (this.referencesUntrustedAlias(spreadExpr.expression) && !hasValidationBoundary(spreadExpr, this.sourceFile)) {
        // Check if spreading into an object
        const parent = spreadExpr.parent;
        if (parent && ts.isObjectLiteralExpression(parent)) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            ruleId: 'BCR-VAL-009',
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
    // Tightened: `.toString()`/`.valueOf()`/`.toJSON()` were removed — they are ubiquitous and are
    // NOT gadget chains by themselves (they produced the dominant false positives). The real
    // prototype-manipulation gadget surface is Object.create / defineProperty / setPrototypeOf /
    // assign and the Function constructor invoked with an untrusted descriptor/key.
    const allCallExpressions = ASTVisitor.findNodes(this.sourceFile, (node) => ts.isCallExpression(node));

    allCallExpressions.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const callee = callExpr.expression;
      const calleeText = callee.getText(this.sourceFile);

      // The gadget primitive must be the CALL ITSELF, not merely present in the text.
      const isGadgetPrimitive =
        /^(Object\.create|Object\.defineProperty|Object\.defineProperties|Object\.setPrototypeOf|Reflect\.set|Reflect\.defineProperty)$/.test(calleeText) ||
        (ts.isPropertyAccessExpression(callee) && callee.name.text === 'constructor');
      if (!isGadgetPrimitive) return;

      const hasUntrustedArg = callExpr.arguments.some((arg) => this.referencesUntrustedAlias(arg));
      if (!hasUntrustedArg || hasValidationBoundary(callExpr, this.sourceFile)) return;

      const { line, column } = this.parser.getLineAndColumn(node.getStart());
      const finding: Finding = {
        ruleId: 'BCR-VAL-010',
        category: 'VALIDATION',
        severity: 'HIGH',
        confidence: 'TENTATIVE',
        verify: 'Confirm the untrusted value controls a property key / prototype descriptor (prototype pollution / gadget), not just a benign value.',
        title: 'Potential Gadget Chain / Prototype Manipulation With Untrusted Input',
        description: 'Untrusted input flows into a prototype/property-manipulation primitive (Object.create / defineProperty / setPrototypeOf / constructor), which can be chained into prototype pollution or code execution.',
        file: this.filePath,
        line,
        column,
        code: node.getText().substring(0, 120),
        recommendation: 'Never pass untrusted data as a property descriptor or prototype. Validate keys against an allowlist and use Object.create(null) / Maps.',
      };

      this.generateDeserializationPoc(finding, 'GADGET_CHAIN');
      this.findings.push(finding);
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
    // Direct sources first (req.body, req.query, etc.).
    if (isUntrustedInputText(text)) {
      return true;
    }

    // Single-identifier accesses can be cheaply matched against the legacy untrusted
    // variable set, but only with strict word-boundary matching against the *first
    // identifier*. Compound expressions are evaluated via the scope-aware tracker
    // through referencesUntrustedAlias() at the AST entry points.
    const tokens = text.split(/[\.\[\]]/);
    const varName = tokens[0].trim();
    if (varName && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(varName) && this.untrustedVariables.has(varName)) {
      return true;
    }

    return false;
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
  private generateDeserializationPoc(finding: Finding, _vulnerabilityType: string): void {
    try {
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
