import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { PocMarkdownReportGenerator } from '../poc/PocMarkdownReportGenerator';
import { ProofOfConcept } from '../poc/types';
import { Logger } from '../utils/logger';
import {
  getEnclosingScopeText,
  getRouteHandlerContexts,
  hasAuthorizationProtection,
  hasOwnershipCheck,
  isSensitiveRouteContext,
  isUserControlledExpression,
} from '../utils/detectorLogic';

/**
 * Access Control Detector
 *
 * Detects access control vulnerabilities and BOLA (Broken Object Level Authorization) issues:
 * - Missing authorization checks on sensitive endpoints
 * - Sequential/predictable IDs without ownership verification
 * - No ownership verification (horizontal privilege escalation)
 * - Vertical privilege escalation (user→admin)
 * - Missing role/permission validation
 * - Direct object reference (IDOR) vulnerabilities
 * - Function-level access control bypass
 *
 * @example
 * const detector = new AccessControlDetector('routes.ts', sourceFile, parser);
 * const result = detector.detect();
 */
export class AccessControlDetector {
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
   * Detects all access control vulnerabilities in the source file
   */
  detect(): DetectorResult {
    this.findings = [];
    this.generatedPocs = [];

    this.detectMissingAuthorizationChecks();
    this.detectBolaVulnerabilities();
    this.detectMissingOwnershipVerification();
    this.detectPrivilegeEscalation();
    this.detectIdorVulnerabilities();

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
   * Detects routes/endpoints missing authorization checks
   */
  private detectMissingAuthorizationChecks(): void {
    const routes = getRouteHandlerContexts(this.sourceFile, this.parser);

    routes.forEach((route) => {
      if (!isSensitiveRouteContext(route) || hasAuthorizationProtection(route)) {
        return;
      }

      const finding: Finding = {
        category: 'ACCESS_CONTROL',
        severity: 'HIGH',
        title: 'Missing Authorization Check on Sensitive Endpoint',
        description: `Route '${route.path}' handles a sensitive action but no role, permission, or ownership guard is visible in middleware or handler logic.`,
        file: this.filePath,
        line: route.line,
        column: 1,
        code: route.routeText.substring(0, 100),
        recommendation: 'Add authorization middleware or inline ownership/role checks before executing sensitive route logic.',
      };

      this.findings.push(finding);
      this.generateAccessControlPoc(finding, route.routeText, route.line);
    });
  }

  /**
   * Detects BOLA vulnerabilities with sequential/predictable IDs
   */
  private detectBolaVulnerabilities(): void {
    const parameterAccess = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isPropertyAccessExpression(node)) {
        const text = node.getText().toLowerCase();
        return /req\.params\..*id|req\.body\..*id|req\.query\..*id/i.test(text);
      }
      return false;
    });

    parameterAccess.forEach((node) => {
      const nodeText = node.getText().toLowerCase();
      const context = getEnclosingScopeText(node, this.sourceFile);
      const isResourceLookupContext = /(findbyid|getbyid|findone|where|query|delete|update|select)/.test(context);

      // Check if the ID is used directly without ownership verification
      const hasOwnershipGuard = hasOwnershipCheck(context);

      if (
        isResourceLookupContext &&
        !hasOwnershipGuard &&
        (nodeText.includes('userid') || nodeText.includes('orderid') || nodeText.includes('invoiceid'))
      ) {
        const { line, column } = this.parser.getLineAndColumn(node.getStart());
        const finding: Finding = {
          category: 'ACCESS_CONTROL',
          severity: 'CRITICAL',
          title: 'BOLA: Predictable ID Used Without Ownership Check',
          description: `The ${nodeText} parameter is accessed directly without verifying that the current user owns this resource. Attackers can enumerate IDs and access other users' data.`,
          file: this.filePath,
          line,
          column,
          code: node.getText(),
          recommendation: 'Always verify that the authenticated user owns the resource before returning it. Check ownership by comparing the resource owner ID with the current user ID.',
        };

        this.findings.push(finding);
        this.generateAccessControlPoc(finding, node.getText(), line);
      }
    });
  }

  /**
   * Detects missing ownership verification (horizontal escalation)
   */
  private detectMissingOwnershipVerification(): void {
    const dbQueries = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        return /find|findById|findOne|query|select|where/i.test(name || '');
      }
      return false;
    });

    dbQueries.forEach((node) => {
      const text = node.getText();
      const parent = getEnclosingScopeText(node, this.sourceFile);

      // If ID is passed but no user/owner check
      if (/id|req\.params|req\.body|req\.query/i.test(text)) {
        const hasOwnerVerification = hasOwnershipCheck(parent) || text.toLowerCase().includes('owner');

        if (!hasOwnerVerification && parent.length > 20) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            category: 'ACCESS_CONTROL',
            severity: 'HIGH',
            title: 'Missing Ownership Verification (Horizontal Escalation)',
            description: 'Database query retrieves a resource by ID without verifying the current user owns it. Attackers can access any resource by changing the ID parameter.',
            file: this.filePath,
            line,
            column,
            code: text.substring(0, 60),
            recommendation: 'Add an additional condition to the query to verify user ownership: AND user_id = req.user.id or similar.',
          };

          this.findings.push(finding);
          this.generateAccessControlPoc(finding, text, line);
        }
      }
    });
  }

  /**
   * Detects privilege escalation vulnerabilities
   */
  private detectPrivilegeEscalation(): void {
    const functions = ASTVisitor.findFunctionDeclarations(this.sourceFile);

    functions.forEach((func) => {
      const funcText = func.getText().toLowerCase();
      const funcName = func.name?.text.toLowerCase() || '';

      // Check for admin/sensitive functions without proper role checks
      if (/admin|delete|update|settings|permissions|role|assign/i.test(funcName)) {
        const hasRoleCheck = hasAuthorizationProtection(funcText);

        if (!hasRoleCheck) {
          const { line, column } = this.parser.getLineAndColumn(func.getStart());
          const finding: Finding = {
            category: 'ACCESS_CONTROL',
            severity: 'CRITICAL',
            title: 'Potential Privilege Escalation (Vertical)',
            description: `Function '${funcName}' performs privileged operations without verifying user role. A regular user might be able to call admin functions.`,
            file: this.filePath,
            line,
            column,
            code: func.getText().substring(0, 60),
            recommendation: 'Add explicit role/permission checks at the beginning of the function. Verify that the user has admin or required privileges.',
          };

          this.findings.push(finding);
          this.generateAccessControlPoc(finding, func.getText().substring(0, 100), line);
        }
      }
    });
  }

  /**
   * Detects IDOR (Insecure Direct Object Reference) vulnerabilities
   */
  private detectIdorVulnerabilities(): void {
    const objectReferences = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        const args = (node as ts.CallExpression).arguments;
        
        return /findById|getById|getOne|findOne/i.test(name || '') && args.length > 0;
      }
      return false;
    });

    objectReferences.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const args = callExpr.arguments;
      
      if (args.length > 0) {
        const firstArg = args[0];
        const isUserInput = isUserControlledExpression(firstArg, this.sourceFile);

        if (isUserInput) {
          const { line, column } = this.parser.getLineAndColumn(node.getStart());
          const finding: Finding = {
            category: 'ACCESS_CONTROL',
            severity: 'CRITICAL',
              title: 'IDOR: Direct Object Reference Without Access Check',
            description: 'Object is accessed directly using user-supplied ID without verifying the user has access permission. This allows attackers to access any object by changing the ID.',
            file: this.filePath,
            line,
            column,
            code: node.getText().substring(0, 60),
            recommendation: 'After retrieving the object, verify that the current user is authorized to access it before returning or modifying it.',
          };

          this.findings.push(finding);
          this.generateAccessControlPoc(finding, node.getText(), line);
        }
      }
    });
  }

  /**
   * Generate POC for an access control finding
   */
  private generateAccessControlPoc(finding: Finding, vulnerableCode: string, line: number): void {
    const poc: ProofOfConcept = {
      id: `access-control-${line}-${Date.now()}`,
      title: finding.title,
      description: finding.description,
      vulnerabilityType: 'ACCESS_CONTROL',
      severity: finding.severity,
      cvssScore: finding.severity === 'CRITICAL' ? 9.1 : finding.severity === 'HIGH' ? 8.2 : 6.5,
      steps: [
        {
          stepNumber: 1,
          actor: 'attacker',
          description: 'Authenticate as a regular user and capture a valid request to a resource endpoint.',
          payload: 'GET /api/users/123/profile',
          expectedResult: '200 OK for owned resource',
        },
        {
          stepNumber: 2,
          actor: 'attacker',
          description: 'Modify the object identifier in the path/query/body to another tenant/resource ID.',
          payload: 'GET /api/users/124/profile',
          expectedResult: 'Request still succeeds due to missing authorization/ownership check',
        },
        {
          stepNumber: 3,
          actor: 'backend',
          description: 'Backend fetches object directly from user-controlled identifier without ownership verification.',
          codeSnippet: vulnerableCode.substring(0, 200),
          filePath: this.filePath,
          lineNumber: line,
        },
      ],
      codeFlow: {
        diagram: '[Attacker] -> [Route Handler] -> [DB lookup by ID] -> [Response]',
        components: [
          { id: 'input', name: 'User-controlled ID', type: 'input', isVulnerable: true, location: `${this.filePath}:${line}` },
          { id: 'handler', name: 'Route Handler', type: 'processing', isVulnerable: true },
          { id: 'db', name: 'Resource Query', type: 'storage', isVulnerable: true },
          { id: 'output', name: 'API Response', type: 'output' },
        ],
        connections: [
          { from: 'input', to: 'handler', isVulnerable: true, label: 'tainted id' },
          { from: 'handler', to: 'db', isVulnerable: true, label: 'findById(id)' },
          { from: 'db', to: 'output', isVulnerable: true, label: 'returns unauthorized object' },
        ],
      },
      rootCause: 'Resource access is authorized by object identifier only, without verifying subject ownership/permissions.',
      businessImpact: 'Attackers can read or modify another user’s records, violating tenant isolation and data confidentiality.',
      technicalImpact: 'IDOR/BOLA enables horizontal privilege escalation across resource IDs.',
      payloads: [
        {
          name: 'ID enumeration',
          content: 'for id in 120 121 122; do curl -H "Authorization: Bearer <token>" /api/users/$id/profile; done',
          contentType: 'bash',
          description: 'Enumerate predictable IDs to access other users’ records.',
          expectedOutput: 'Sensitive records for non-owned IDs are returned.',
          difficulty: 'easy',
          successRate: 90,
        },
      ],
      remediationCode: `// Enforce ownership check before returning resource\nif (resource.userId !== req.user.id && !req.user.isAdmin) {\n  return res.status(403).json({ error: 'Forbidden' });\n}`,
      remediationDescription: 'Enforce object-level authorization by verifying resource ownership or role permissions before read/update actions.',
      owaspCategory: 'A01:2021 - Broken Access Control',
      generatedAt: new Date(),
      pocVersion: '2.0',
    };

    this.generatedPocs.push(poc);
  }
}
