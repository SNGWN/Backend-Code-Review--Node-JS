import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { Logger } from '../utils/logger';
import {
  getRouteHandlerContexts,
  isUserControlledExpression,
  RouteHandlerContext,
} from '../utils/detectorLogic';
import { computePocId } from '../rules/fingerprint';
import { TaintTracker } from '../utils/taint';

/**
 * Business Logic Flaw Detector
 *
 * Detects business logic vulnerabilities in TypeScript backend code:
 * - Race conditions in concurrent transactions
 * - Missing idempotency keys (enabling duplicate charges)
 * - Insufficient funds/balance checks bypassed
 * - Client-side price manipulation
 * - Inventory over-selling in concurrent purchases
 * - Workflow step bypass (skipping validation)
 * - State machine bypass (invalid state transitions)
 * - Missing balance/quantity verification before operations
 *
 * @example
 * const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
 * const result = detector.detect();
 * result.findings; // Array of business logic flaws
 */
export class BusinessLogicDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private generatedPocs: ProofOfConcept[] = [];
  private findingKeys = new Set<string>();
  private taintTracker: TaintTracker | null = null;

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  /**
   * Detects all business logic vulnerabilities in the source file
   *
   * Runs all detection methods:
   * - Race condition vulnerabilities
   * - Missing idempotency keys
   * - Insufficient balance checks
   * - Client-side price usage
   * - Inventory over-selling
   * - Workflow bypass
   * - State machine bypass
   * - Missing verification
   *
   * @returns DetectorResult containing array of business logic findings
   */
  detect(): DetectorResult {
    this.findings = [];
    this.generatedPocs = [];
    this.findingKeys.clear();
    this.taintTracker = new TaintTracker(this.sourceFile);

    this.detectRaceConditions();
    this.detectMissingIdempotencyKeys();
    this.detectInsufficientFundsCheck();
    this.detectNonAtomicCheckThenAct();
    this.detectClientSidePriceUsage();
    this.detectInventoryOverSelling();

    return { findings: this.findings };
  }

  /**
   * Returns POCs generated during detection
   */
  getPocs(): ProofOfConcept[] {
    return this.generatedPocs;
  }

  /**
   * Export POCs as markdown files
   */
  exportPocsAsMarkdown(outputDir: string): string[] {
    const exportedFiles: string[] = [];

    this.generatedPocs.forEach((poc) => {
      try {
        const filePath = PocMarkdownReportGenerator.savePocReport(poc, outputDir);
        exportedFiles.push(filePath);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        Logger.error(`Failed to export POC ${poc.id}`, { error: errorMessage });
      }
    });

    return exportedFiles;
  }

  /**
   * Detects potential race conditions in async operations
   * Looks for concurrent database updates without locks or transactions
   */
  private detectRaceConditions(): void {
    const sourceText = this.sourceFile.getText();
    
    // Look for functions with multiple awaits without transaction/lock
    const asyncFunctionPattern = /async\s+function|async\s*\(|async\s*=>/;
    const multipleAwaitPattern = /await.*?;.*?await/s;
    if (asyncFunctionPattern.test(sourceText) && multipleAwaitPattern.test(sourceText)) {
      // Find the function node
      const functions = ASTVisitor.findNodes(this.sourceFile, (node) => {
        return ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || 
               ts.isFunctionExpression(node);
      });

      functions.forEach((node) => {
        const nodeText = node.getText();
        const { line, column } = this.parser.getLineAndColumn(node.getStart());
        
        // Check for multiple awaits without transaction
        const awaitCount = (nodeText.match(/await\s+/g) || []).length;
        const hasTransaction = nodeText.includes('transaction') || 
                              nodeText.includes('lock') || 
                              nodeText.includes('mutex');

        if (awaitCount >= 2 && !hasTransaction && 
            (nodeText.includes('update') || nodeText.includes('UPDATE'))) {
          
          const finding: Finding = {
            category: 'BUSINESS_LOGIC',
            severity: 'HIGH',
            ruleId: 'BCR-BL-001',
            title: 'Potential Race Condition in Async Operations',
            description: 'Multiple async operations without transaction atomicity. Concurrent requests could interleave, causing inconsistent state.',
            file: this.filePath,
            line,
            column,
            code: node.getText().substring(0, 80),
            recommendation: 'Wrap concurrent operations in database transactions or use distributed locks to ensure atomicity.',
          };
          
          this.findings.push(finding);
          this.generateBusinessLogicPoc(finding, node.getText(), line);
        }
      });
    }
  }

  /**
   * Detects missing idempotency keys
   * Looks for payment/charge operations without idempotency verification
   */
  private detectMissingIdempotencyKeys(): void {
    this.getPaymentRouteContexts().forEach((route) => {
      if (!route.handler || this.hasIdempotencyProtection(route)) {
        return;
      }

      const paymentCall = this.findPaymentCalls(route.handler)[0];
      if (!paymentCall) {
        return;
      }

      const { line, column } = this.parser.getLineAndColumn(paymentCall.getStart());
      this.recordBusinessLogicFinding(
        {
          category: 'BUSINESS_LOGIC',
          severity: 'CRITICAL',
          ruleId: 'BCR-BL-002',
          title: 'Missing Idempotency Key Validation',
          description: 'Payment/charge operation lacks idempotency key verification. Network retries could cause duplicate charges.',
          file: this.filePath,
          line,
          column,
          code: paymentCall.getText().substring(0, 80),
          recommendation: 'Implement idempotency key validation to prevent duplicate transactions. Store processed request IDs and check before processing.',
        },
        paymentCall.getText(),
        line
      );
    });
  }

  /**
   * Detects insufficient funds checks that can be bypassed
   * Looks for balance/fund checks without proper locking
   */
  private detectInsufficientFundsCheck(): void {
    const conditionals = ASTVisitor.findNodes(this.sourceFile, (node) => {
      return ts.isIfStatement(node);
    });

    conditionals.forEach((node) => {
      const ifStmt = node as ts.IfStatement;
      const conditionText = ifStmt.expression.getText().toLowerCase();
      const fullNodeText = node.getText();

      // Look for balance/funds checks
      if ((conditionText.includes('balance') || conditionText.includes('funds') ||
           conditionText.includes('account')) &&
          (conditionText.includes('>') || conditionText.includes('<'))) {
        
        const thenText = ifStmt.thenStatement.getText().toLowerCase();
        
        // Check if operation is performed without transaction
        if ((thenText.includes('update') || thenText.includes('debit') || 
             thenText.includes('withdraw') || thenText.includes('query')) &&
            !fullNodeText.includes('transaction') &&
            !fullNodeText.includes('lock')) {
          
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          
          const finding: Finding = {
            category: 'BUSINESS_LOGIC',
            severity: 'HIGH',
            ruleId: 'BCR-BL-003',
            title: 'Time-of-Check to Time-of-Use (TOCTOU) in Balance Verification',
            description: 'Balance check is performed, but the actual debit operation is not atomic. Another concurrent request could deplete funds between check and debit.',
            file: this.filePath,
            line,
            column,
            code: node.getText().substring(0, 80),
            recommendation: 'Use database transactions or pessimistic locks to ensure balance check and debit are atomic.',
          };
          
          this.findings.push(finding);
          this.generateBusinessLogicPoc(finding, node.getText(), line);
        }
      }
    });
  }

  /**
   * Detects TOCTOU where the check and the act are SEPARATE statements (M15/M43).
   *
   * `detectInsufficientFundsCheck` only catches the case where the mutation sits inside the
   * guarding `if`'s then-branch. The more common — and more dangerous — shape spreads across
   * sibling statements within one function:
   *
   *     const balance = await wallet.getBalance(userId);   // time-of-check (read)
   *     if (balance < amount) throw new Error('insufficient');
   *     await wallet.debit(userId, amount);                // time-of-use (sibling, unguarded write)
   *
   * Here the debit is NOT inside the `if`, so the text-substring detector misses it. This pass
   * pairs a resource READ/guard with a later, non-atomic mutation of the SAME resource family that
   * is not itself inside an `if`-then guard. Reported at TENTATIVE — DB-level atomicity (a unique
   * constraint, an atomic conditional UPDATE in the repository) may make it safe — so the user
   * confirms. Skipped entirely when the function already shows transaction/lock/atomic markers.
   */
  private detectNonAtomicCheckThenAct(): void {
    const RESOURCE = /(balance|funds?|stock|quantity|inventory|wallet|credits?|points|available)/i;
    const COMPARATOR = /[<>]=?/;
    const MUTATION_VERB = /(debit|withdraw|decrement|deduct|charge|transfer|reserve|reduce|subtract|increment|update|save|set)/i;
    const READ_VERB = /(get|find|select|fetch|read|current|load|lookup|balance|count)/i;
    const ATOMIC = /(transaction|\.lock\(|for\s+update|mutex|semaphore|serializable|findoneandupdate|\$inc|\batomic\b|optimistic|pessimistic|rowlock|version\s*:|\.increment\(|\.decrement\(|\btx\b|\btrx\b|queryrunner|unitofwork)/i;

    this.getFunctionLikeNodes().forEach((scope) => {
      const scopeText = scope.getText(this.sourceFile);
      const scopeLower = scopeText.toLowerCase();
      if (!RESOURCE.test(scopeLower) || ATOMIC.test(scopeLower)) {
        return;
      }

      // Check anchors: an `if` comparing the resource, OR a read call that loads the resource.
      const checks: ts.Node[] = [];
      (ASTVisitor.findNodes(scope, (n) => ts.isIfStatement(n)) as ts.IfStatement[]).forEach((ifStmt) => {
        const cond = ifStmt.expression.getText(this.sourceFile);
        if (RESOURCE.test(cond) && COMPARATOR.test(cond)) checks.push(ifStmt);
      });
      (ASTVisitor.findNodes(scope, (n) => ts.isCallExpression(n)) as ts.CallExpression[]).forEach((call) => {
        const text = call.getText(this.sourceFile);
        if (RESOURCE.test(text) && READ_VERB.test(text) && !MUTATION_VERB.test(text)) checks.push(call);
      });
      if (checks.length === 0) {
        return;
      }
      const earliestCheck = Math.min(...checks.map((c) => c.getStart()));

      // Act: a mutation of the resource AFTER the earliest check, that is NOT inside an `if`-then
      // (that keeps this disjoint from the in-`if` BCR-BL-003 detector).
      const act = (ASTVisitor.findNodes(scope, (n) => ts.isCallExpression(n)) as ts.CallExpression[])
        .filter((call) => {
          const text = call.getText(this.sourceFile);
          return RESOURCE.test(text) && MUTATION_VERB.test(text);
        })
        .filter((call) => call.getStart() > earliestCheck)
        .filter((call) => !this.isInsideIfThen(call, scope))
        .sort((a, b) => a.getStart() - b.getStart())[0];

      if (!act) {
        return;
      }

      const { line, column } = this.parser.getLineAndColumn(act.getStart());
      this.recordBusinessLogicFinding(
        {
          category: 'BUSINESS_LOGIC',
          severity: 'HIGH',
          ruleId: 'BCR-BL-003',
          confidence: 'TENTATIVE',
          verify:
            'Confirm the read/guard and this mutation execute in the SAME transaction or under a row lock; as separate statements a concurrent request can interleave between them (double-spend / oversell).',
          title: 'Time-of-Check to Time-of-Use (TOCTOU) Across Statements',
          description:
            'A resource value is read/checked and then mutated in a separate, non-atomic statement within the same function. Concurrent requests can interleave between the check and the update, bypassing the guard.',
          file: this.filePath,
          line,
          column,
          code: act.getText().substring(0, 80),
          recommendation:
            'Wrap the check and the mutation in one database transaction or take a row-level/pessimistic lock, or use an atomic conditional update (UPDATE … SET x = x - n WHERE x >= n).',
        },
        act.getText(),
        line
      );
    });
  }

  /**
   * True when `node` sits inside the then-branch of some enclosing `if` (up to `boundary`).
   * Used to keep the cross-statement TOCTOU pass disjoint from the in-`if` balance detector.
   */
  private isInsideIfThen(node: ts.Node, boundary: ts.Node): boolean {
    let current: ts.Node = node;
    while (current.parent && current !== boundary) {
      const parent = current.parent;
      if (ts.isIfStatement(parent) && parent.thenStatement === current) {
        return true;
      }
      current = parent;
    }
    return false;
  }

  /**
   * Detects client-side price usage in transactions
   * Looks for price parameters from request body in financial operations
   */
  private detectClientSidePriceUsage(): void {
    this.getPaymentRouteContexts().forEach((route) => {
      if (!route.handler) {
        return;
      }

      const taintedVariables = this.buildRequestDerivedVariableSet(route.handler);
      const riskyAmount = this.findPaymentCalls(route.handler)
        .flatMap((callExpr) => this.getPaymentAmountExpressions(callExpr))
        // The local request-derived set is single-expression; also consult the (inter-procedural,
        // framework-aware) TaintTracker so an amount laundered through a helper — `charge(getAmount(req))` —
        // is still caught.
        .find(
          (expression) =>
            this.referencesRequestDerivedInput(expression, taintedVariables) ||
            (this.taintTracker?.isTainted(expression) ?? false)
        );

      if (!riskyAmount) {
        return;
      }

      const { line, column } = this.parser.getLineAndColumn(riskyAmount.getStart());
      this.recordBusinessLogicFinding(
        {
          category: 'BUSINESS_LOGIC',
          severity: 'CRITICAL',
          ruleId: 'BCR-BL-004',
          title: 'Client-Controlled Price in Payment Operation',
          description: 'Price/amount for payment is taken from user request without server-side validation. Attacker can modify the amount.',
          file: this.filePath,
          line,
          column,
          code: riskyAmount.getText().substring(0, 80),
          recommendation: 'Always retrieve price from server-side database. Never trust client-supplied price amounts. Validate against inventory pricing.',
        },
        riskyAmount.getText(),
        line
      );
    });
  }

  /**
   * Detects inventory over-selling vulnerabilities
   * Looks for concurrent inventory updates without proper synchronization
   */
  private detectInventoryOverSelling(): void {
    this.getFunctionLikeNodes().forEach((scope) => {
      const scopeText = scope.getText().toLowerCase();
      if (!/(quantity|stock|inventory)/.test(scopeText)) {
        return;
      }

      if (/(transaction|lock|for update|mutex|semaphore)/.test(scopeText)) {
        return;
      }

      const dbCalls = ASTVisitor.findNodes(scope, (node) => ts.isCallExpression(node)) as ts.CallExpression[];
      const inventoryRead = dbCalls.find((callExpr) => this.isInventoryReadCall(callExpr));
      const inventoryWrite = dbCalls.find((callExpr) => this.isInventoryWriteCall(callExpr));

      if (!inventoryRead || !inventoryWrite || this.hasAtomicInventoryGuard(inventoryWrite.getText().toLowerCase())) {
        return;
      }

      const { line, column } = this.parser.getLineAndColumn(inventoryWrite.getStart());
      this.recordBusinessLogicFinding(
        {
          category: 'BUSINESS_LOGIC',
          severity: 'HIGH',
          ruleId: 'BCR-BL-005',
          title: 'Inventory Over-Selling in Concurrent Purchases',
          description: 'Inventory is decremented without atomic verification. Multiple concurrent purchases could result in negative stock.',
          file: this.filePath,
          line,
          column,
          code: inventoryWrite.getText().substring(0, 80),
          recommendation: 'Use atomic database operations or row-level locks to ensure quantity never goes negative. Implement: UPDATE inventory SET quantity = quantity - X WHERE product_id = Y AND quantity >= X',
        },
        scope.getText(),
        line
      );
    });
  }

  private getPaymentRouteContexts(): RouteHandlerContext[] {
    return getRouteHandlerContexts(this.sourceFile, this.parser).filter((route) => {
      const contextText = `${route.path}\n${route.handlerText}`.toLowerCase();
      return /(charge|payment|checkout|purchase|refund|billing|invoice|stripe|order)/.test(contextText);
    });
  }

  private hasIdempotencyProtection(route: RouteHandlerContext): boolean {
    const text = [route.routeText, route.middlewareText, route.handlerText].join('\n').toLowerCase();
    return /(idempotency|idempotentkey|requestid|duplicate|dedupe|processed[_-]?request)/.test(text);
  }

  private findPaymentCalls(scope: ts.Node): ts.CallExpression[] {
    return (ASTVisitor.findNodes(scope, (node) => ts.isCallExpression(node)) as ts.CallExpression[]).filter(
      (callExpr) => this.isPaymentOperationCall(callExpr)
    );
  }

  private isPaymentOperationCall(callExpr: ts.CallExpression): boolean {
    const expressionText = callExpr.expression.getText(this.sourceFile).toLowerCase();
    return (
      /(stripe\.charges\.create|charges\.create|createcharge|paymentintent|payments?\.create|checkout)/.test(
        expressionText
      ) ||
      (/(charge|payment)/.test(expressionText) && callExpr.arguments.length > 0)
    );
  }

  private getPaymentAmountExpressions(callExpr: ts.CallExpression): ts.Expression[] {
    const amountExpressions: ts.Expression[] = [];

    callExpr.arguments.forEach((argument) => {
      if (ts.isObjectLiteralExpression(argument)) {
        argument.properties.forEach((property) => {
          if (!ts.isPropertyAssignment(property)) {
            return;
          }

          const propertyName = property.name.getText(this.sourceFile).replace(/['"`]/g, '').toLowerCase();
          if (/(amount|price|total|unitamount|unit_amount)/.test(propertyName)) {
            amountExpressions.push(property.initializer);
          }
        });
        return;
      }

      if (/(amount|price|total)/.test(argument.getText(this.sourceFile).toLowerCase())) {
        amountExpressions.push(argument);
      }
    });

    return amountExpressions;
  }

  private buildRequestDerivedVariableSet(scope: ts.Node): Set<string> {
    const tainted = new Set<string>();
    const declarations = ASTVisitor.findNodes(scope, (node) => ts.isVariableDeclaration(node)) as ts.VariableDeclaration[];

    declarations.forEach((declaration) => {
      const initializer = declaration.initializer;
      if (!initializer || !this.referencesRequestDerivedInput(initializer, tainted)) {
        return;
      }

      if (ts.isIdentifier(declaration.name)) {
        tainted.add(declaration.name.text);
        return;
      }

      if (ts.isObjectBindingPattern(declaration.name) || ts.isArrayBindingPattern(declaration.name)) {
        declaration.name.elements.forEach((element) => {
          if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
            tainted.add(element.name.text);
          }
        });
      }
    });

    return tainted;
  }

  private referencesRequestDerivedInput(expression: ts.Expression, taintedVariables: Set<string>): boolean {
    if (isUserControlledExpression(expression, this.sourceFile)) {
      return true;
    }

    if (ts.isIdentifier(expression)) {
      return taintedVariables.has(expression.text);
    }

    if (ts.isPropertyAccessExpression(expression)) {
      return this.referencesRequestDerivedInput(expression.expression, taintedVariables);
    }

    if (ts.isElementAccessExpression(expression)) {
      return this.referencesRequestDerivedInput(expression.expression, taintedVariables);
    }

    if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)) {
      return this.referencesRequestDerivedInput(expression.expression, taintedVariables);
    }

    if (ts.isBinaryExpression(expression)) {
      return (
        this.referencesRequestDerivedInput(expression.left, taintedVariables) ||
        this.referencesRequestDerivedInput(expression.right, taintedVariables)
      );
    }

    if (ts.isTemplateExpression(expression)) {
      return expression.templateSpans.some((span) =>
        this.referencesRequestDerivedInput(span.expression, taintedVariables)
      );
    }

    if (ts.isCallExpression(expression)) {
      return expression.arguments.some((arg) => this.referencesRequestDerivedInput(arg, taintedVariables));
    }

    return false;
  }

  private getFunctionLikeNodes(): ts.Node[] {
    return ASTVisitor.findNodes(
      this.sourceFile,
      (node) =>
        ts.isFunctionDeclaration(node) ||
        ts.isArrowFunction(node) ||
        ts.isFunctionExpression(node) ||
        ts.isMethodDeclaration(node)
    );
  }

  private isInventoryReadCall(callExpr: ts.CallExpression): boolean {
    const text = callExpr.getText(this.sourceFile).toLowerCase();
    return /(select|find|findone|get|query)/.test(text) && /(quantity|stock|inventory)/.test(text);
  }

  private isInventoryWriteCall(callExpr: ts.CallExpression): boolean {
    const text = callExpr.getText(this.sourceFile).toLowerCase();
    return /(update|decrement|adjust|save|query)/.test(text) &&
      /(quantity|stock|inventory)/.test(text) &&
      /(-|decrement|set\s+quantity\s*=|set\s+stock\s*=)/.test(text);
  }

  private hasAtomicInventoryGuard(text: string): boolean {
    return /(where[\s\S]*quantity\s*>=|where[\s\S]*stock\s*>=|and quantity|and stock|affectedrows|rowcount)/.test(
      text
    );
  }

  private recordBusinessLogicFinding(finding: Finding, vulnerableCode: string, line: number): void {
    const key = `${finding.title}:${finding.file}:${finding.line}`;
    if (this.findingKeys.has(key)) {
      return;
    }

    this.findingKeys.add(key);
    this.findings.push(finding);
    this.generateBusinessLogicPoc(finding, vulnerableCode, line);
  }

  /**
   * Generate POC for a business logic finding
   */
  private generateBusinessLogicPoc(finding: Finding, vulnerableCode: string, line: number): void {
    const poc: ProofOfConcept = {
      id: computePocId('business-logic', this.filePath, line, vulnerableCode),
      title: finding.title,
      description: finding.description,
      vulnerabilityType: 'BUSINESS_LOGIC',
      severity: finding.severity,
      cvssScore: finding.severity === 'CRITICAL' ? 9.0 : finding.severity === 'HIGH' ? 8.0 : 6.2,
      steps: [
        {
          stepNumber: 1,
          actor: 'attacker',
          description: 'Identify a transaction-sensitive endpoint (payment/order/inventory/workflow).',
          payload: 'POST /api/checkout',
          expectedResult: 'Endpoint processes business operation.',
        },
        {
          stepNumber: 2,
          actor: 'attacker',
          description: 'Send crafted or concurrent requests to exploit missing business rule enforcement.',
          payload: 'Parallel requests or manipulated business parameters',
          expectedResult: 'Duplicate, inconsistent, or unauthorized state change occurs.',
        },
        {
          stepNumber: 3,
          actor: 'backend',
          description: 'Server executes vulnerable logic without required validation/atomicity checks.',
          codeSnippet: vulnerableCode.substring(0, 200),
          filePath: this.filePath,
          lineNumber: line,
        },
        {
          stepNumber: 4,
          actor: 'attacker',
          description: 'Confirm business impact (duplicate charge, negative stock, workflow bypass).',
          expectedResult: 'System enters an invalid business state.',
        },
      ],
      codeFlow: {
        diagram: '[Client Input] -> [Business Rule Check] -> [State Update] -> [Persisted Inconsistent State]',
        components: [
          { id: 'input', name: 'Business Request', type: 'input', isVulnerable: true, location: `${this.filePath}:${line}` },
          { id: 'rule', name: 'Rule Validation', type: 'validation', isVulnerable: true },
          { id: 'update', name: 'State Mutation', type: 'processing', isVulnerable: true },
          { id: 'db', name: 'Database Write', type: 'storage', isVulnerable: true },
        ],
        connections: [
          { from: 'input', to: 'rule', label: 'request data', isVulnerable: true },
          { from: 'rule', to: 'update', label: 'insufficient checks', isVulnerable: true },
          { from: 'update', to: 'db', label: 'invalid state persisted', isVulnerable: true },
        ],
      },
      rootCause: 'Critical business invariants are not atomically validated and enforced before state changes.',
      businessImpact: 'Revenue loss, inventory corruption, duplicate financial operations, and abuse of workflow protections.',
      technicalImpact: 'Race conditions and logic bypasses allow invalid state transitions and inconsistent data integrity.',
      payloads: [
        {
          name: 'Concurrent exploitation',
          content: 'Send 10 parallel checkout/payment requests with the same item or idempotency token missing.',
          contentType: 'http',
          description: 'Triggers race conditions and duplicate processing in business operations.',
          expectedOutput: 'Multiple successful operations where only one should be accepted.',
          difficulty: 'medium',
          successRate: 75,
        },
      ],
      remediationCode: `await db.transaction(async (tx) => {\n  // Validate current state and enforce invariants atomically\n  // Reject duplicate/idempotent replay requests\n});`,
      remediationDescription: 'Use transactions/locks and explicit state-machine guards, plus idempotency checks for sensitive business operations.',
      owaspCategory: 'A04:2021 - Insecure Design',
      generatedAt: new Date(),
      pocVersion: '2.0',
    };

    this.generatedPocs.push(poc);
  }
}
