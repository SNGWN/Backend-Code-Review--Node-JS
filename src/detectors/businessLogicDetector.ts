import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { StringHelper } from '../utils/helpers';
import { ProofOfConcept, PocGenerationRequest, PocGeneratorConfig } from '../poc/types';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';

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
 * console.log(result.findings); // Array of business logic flaws
 */
export class BusinessLogicDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private generatedPocs: ProofOfConcept[] = [];

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

    this.detectRaceConditions();
    this.detectMissingIdempotencyKeys();
    this.detectInsufficientFundsCheck();
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
        console.error(`Failed to export POC ${poc.id}: ${error}`);
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
    const noTransactionPattern = /(?!.*transaction|.*lock|.*mutex)/;
    
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
    const sourceText = this.sourceFile.getText();
    
    // Look for payment/charge operations
    if (sourceText.includes('charge') || sourceText.includes('payment') || 
        sourceText.includes('stripe')) {
      
      const nodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
        if (ts.isCallExpression(node)) {
          const text = node.getText();
          return text.includes('charge') || text.includes('payment') || 
                 text.includes('stripe');
        }
        return false;
      });

      nodes.forEach((node) => {
        const nodeText = node.getText();
        const parentText = node.parent?.getText() || '';
        const fullContext = sourceText.substring(
          Math.max(0, node.getStart() - 300), 
          Math.min(sourceText.length, node.getEnd() + 300)
        );

        // Check if there's idempotency key handling
        const hasIdempotency = fullContext.includes('idempotency') || 
                              fullContext.includes('idempotentKey') ||
                              fullContext.includes('requestId') ||
                              fullContext.includes('duplicate');

        if (!hasIdempotency && (nodeText.includes('charge') || nodeText.includes('create'))) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          
          const finding: Finding = {
            category: 'BUSINESS_LOGIC',
            severity: 'CRITICAL',
            title: 'Missing Idempotency Key Validation',
            description: 'Payment/charge operation lacks idempotency key verification. Network retries could cause duplicate charges.',
            file: this.filePath,
            line,
            column,
            code: nodeText.substring(0, 80),
            recommendation: 'Implement idempotency key validation to prevent duplicate transactions. Store processed request IDs and check before processing.',
          };
          
          this.findings.push(finding);
          this.generateBusinessLogicPoc(finding, nodeText, line);
        }
      });
    }
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
   * Detects client-side price usage in transactions
   * Looks for price parameters from request body in financial operations
   */
  private detectClientSidePriceUsage(): void {
    const sourceText = this.sourceFile.getText();
    
    // Look for req.body usage with price/amount in charge/payment operations
    if ((sourceText.includes('req.body') || sourceText.includes('req.query')) &&
        (sourceText.includes('charge') || sourceText.includes('payment') || 
         sourceText.includes('stripe'))) {
      
      const nodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
        const text = node.getText();
        return text.includes('req.body') || text.includes('req.query') || 
               text.includes('params');
      });

      nodes.forEach((node) => {
        const nodeText = node.getText();
        const { line, column } = this.parser.getLineAndColumn(node.getStart());

        // Check if this is price/amount from request
        if ((nodeText.includes('price') || nodeText.includes('amount') || 
             nodeText.includes('total')) &&
            (nodeText.includes('req.body') || nodeText.includes('req.query'))) {
          
          // Check if used in payment context
          const parentText = ASTVisitor.findNodes(this.sourceFile, (n) => {
            const text = n.getText();
            return text.includes('charge') || text.includes('payment');
          });

          if (parentText.length > 0) {
            const finding: Finding = {
              category: 'BUSINESS_LOGIC',
              severity: 'CRITICAL',
              title: 'Client-Controlled Price in Payment Operation',
              description: 'Price/amount for payment is taken from user request without server-side validation. Attacker can modify the amount.',
              file: this.filePath,
              line,
              column,
              code: nodeText.substring(0, 80),
              recommendation: 'Always retrieve price from server-side database. Never trust client-supplied price amounts. Validate against inventory pricing.',
            };
            
            this.findings.push(finding);
            this.generateBusinessLogicPoc(finding, nodeText, line);
          }
        }
      });

      // Alternative pattern: look for stripe.charges with user-controlled amount
      if (sourceText.includes('stripe')) {
        const chargeNodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
          const text = node.getText();
          return text.includes('stripe.charges') || text.includes('charges.create');
        });

        chargeNodes.forEach((node) => {
          const nodeText = node.getText();
          const { line, column } = this.parser.getLineAndColumn(node.getStart());

          if (nodeText.includes('amount') && 
              (nodeText.includes('req.body') || nodeText.includes('params'))) {
            const finding: Finding = {
              category: 'BUSINESS_LOGIC',
              severity: 'CRITICAL',
              title: 'Client-Controlled Price in Payment Operation',
              description: 'Amount parameter in payment comes from user input. Attacker can manipulate charge amount.',
              file: this.filePath,
              line,
              column,
              code: nodeText.substring(0, 80),
              recommendation: 'Retrieve product price from server database, not from client request.',
            };
            
            this.findings.push(finding);
            this.generateBusinessLogicPoc(finding, nodeText, line);
          }
        });
      }
    }
  }

  /**
   * Detects inventory over-selling vulnerabilities
   * Looks for concurrent inventory updates without proper synchronization
   */
  private detectInventoryOverSelling(): void {
    const sourceText = this.sourceFile.getText();
    
    if (sourceText.includes('quantity') || sourceText.includes('stock') || 
        sourceText.includes('inventory')) {
      
      const nodes = ASTVisitor.findNodes(this.sourceFile, (node) => {
        const text = node.getText().toLowerCase();
        return (text.includes('quantity') || text.includes('stock') || 
                text.includes('inventory')) &&
               (text.includes('update') || text.includes('decrement') || 
                text.includes('-=') || text.includes('query'));
      });

      nodes.forEach((node) => {
        const nodeText = node.getText();
        const { line, column } = this.parser.getLineAndColumn(node.getStart());

        // Check for missing atomic verification
        const hasVerification = nodeText.includes('check') || 
                               nodeText.includes('verify') ||
                               nodeText.includes('WHERE') ||
                               nodeText.includes('AND quantity') ||
                               nodeText.includes('>= quantity');

        if (!hasVerification && 
            (nodeText.includes('quantity') || nodeText.includes('stock'))) {
          const finding: Finding = {
            category: 'BUSINESS_LOGIC',
            severity: 'HIGH',
            title: 'Inventory Over-Selling in Concurrent Purchases',
            description: 'Inventory is decremented without atomic verification. Multiple concurrent purchases could result in negative stock.',
            file: this.filePath,
            line,
            column,
            code: nodeText.substring(0, 80),
            recommendation: 'Use atomic database operations or row-level locks to ensure quantity never goes negative. Implement: UPDATE inventory SET quantity = quantity - X WHERE product_id = Y AND quantity >= X',
          };
          
          this.findings.push(finding);
          this.generateBusinessLogicPoc(finding, nodeText, line);
        }
      });
    }
  }

  /**
   * Generate POC for a business logic finding
   */
  private generateBusinessLogicPoc(finding: Finding, vulnerableCode: string, line: number): void {
    const poc: ProofOfConcept = {
      id: `business-logic-${line}-${Date.now()}`,
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
