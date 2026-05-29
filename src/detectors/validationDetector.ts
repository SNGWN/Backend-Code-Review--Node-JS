import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { StringHelper } from '../utils/helpers';
import { InjectionPocGenerator } from '../poc/templates/InjectionPocGenerator';
import { ProofOfConcept, PocGenerationRequest } from '../poc/types';
import { Logger } from '../utils/logger';
import {
  hasValidationBoundary,
  isUntrustedInputText,
} from '../utils/detectorLogic';
import { TaintTracker } from '../utils/taint';
import { buildImportAliasMap, ImportAlias, resolveCalleeToExportedName } from '../utils/importAliases';

/**
 * Parameter Validation Detector
 *
 * Detects exploitable input-handling weaknesses in TypeScript backend code:
 * - Untrusted request data flowing into raw SQL construction
 * - Untrusted request data flowing into command/code execution
 * - Untrusted request data reaching file-system sinks without path validation
 *
 * Tracks which variables have been validated to reduce false positives.
 * Uses validation library detection to identify validated inputs.
 *
 * @example
 * const detector = new ParameterValidationDetector('routes.ts', sourceFile, parser);
 * const result = detector.detect();
 * result.findings; // Array of validation issues
 */
export class ParameterValidationDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  /**
   * Set of variable names that have been validated using validation libraries
   * Helps avoid false positives for validated inputs
   */
  private validatedVariables = new Set<string>();
  private taintedVariables = new Set<string>();
  private taintTracker: TaintTracker | null = null;
  private aliasMap: Map<string, ImportAlias> = new Map();

  /**
   * POC Generator for injection vulnerabilities
   */
  private pocGenerator: InjectionPocGenerator = new InjectionPocGenerator();

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  /**
   * Detects all parameter validation issues in the source file
   *
     * Runs taint-focused detection against dangerous sinks.
   *
   * @returns DetectorResult containing array of validation findings
   */
  detect(): DetectorResult {
    this.findings = [];
    this.validatedVariables.clear();
    this.taintedVariables.clear();
    this.taintTracker = new TaintTracker(this.sourceFile);
    this.aliasMap = buildImportAliasMap(this.sourceFile);

    this.buildValidationMap();
    this.buildTaintMap();
    this.detectDangerousSinkUsage();
    this.detectTaggedTemplateSqlInjection();

    return { findings: this.findings };
  }

  /**
   * Detects tagged template literals used as SQL builders with user-controlled
   * substitutions. Pattern: `sql\`SELECT * FROM x WHERE id=${req.params.id}\``.
   *
   * Common tag identifiers in the ecosystem: `sql`, `SQL`, `db.sql`, `slonik.sql`,
   * `prisma.$queryRawUnsafe`. We anchor on these names rather than substring-match
   * to keep FP low (e.g. `html\`...\``, `css\`...\``, `gql\`...\`` are out of scope).
   */
  private detectTaggedTemplateSqlInjection(): void {
    const tagged = ASTVisitor.findNodes(this.sourceFile, (node) => ts.isTaggedTemplateExpression(node));
    tagged.forEach((node) => {
      const tagExpr = (node as ts.TaggedTemplateExpression).tag;
      const tagText = tagExpr.getText(this.sourceFile);
      if (!/^(sql|SQL|db\.sql|slonik\.sql|raw|knex\.raw|prisma\.\$queryRaw(?:Unsafe)?|pgPromise\.as)$/.test(tagText)) {
        return;
      }
      const template = (node as ts.TaggedTemplateExpression).template;
      if (!ts.isTemplateExpression(template)) return;

      const taintedSpan = template.templateSpans.find((span) => this.referencesTaintedInput(span.expression));
      if (!taintedSpan) return;

      const { line, column } = this.parser.getLineAndColumn(node.getStart());
      this.findings.push({
        ruleId: 'BCR-VAL-011',
        category: 'VALIDATION',
        severity: 'CRITICAL',
        title: 'SQL Injection via Tagged-Template With Tainted Substitution',
        description: 'A tagged SQL template embeds user-controlled data as a substitution. Most SQL template tags do NOT auto-parameterize substitutions.',
        file: this.filePath,
        line,
        column,
        code: node.getText().substring(0, 160),
        recommendation:
          'Use parameterized placeholders (driver-specific `?` or `$1`) or constrain dynamic field names through a server-side allowlist.',
      });
    });
  }

  /**
   * Builds a map of validated variables
   * Scans for validation library calls (joi, yup, zod, etc.)
   * and tracks which variables have been validated
   *
   * @private
   */
  private buildValidationMap(): void {
    const validationCalls = ASTVisitor.findNodes(this.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const name = ASTVisitor.getCallExpressionName(node);
        return !!(name && StringHelper.isValidationLibraryCall(name));
      }
      return false;
    });

    validationCalls.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      if (callExpr.arguments.length > 0) {
        const firstArg = callExpr.arguments[0];
        const varName = ASTVisitor.getIdentifierName(firstArg);
        if (varName) {
          this.validatedVariables.add(varName);
        }
      }
    });
  }

  private buildTaintMap(): void {
    const variableDeclarations = ASTVisitor.findNodes(
      this.sourceFile,
      (node) => ts.isVariableDeclaration(node)
    );

    variableDeclarations.forEach((node) => {
      const declaration = node as ts.VariableDeclaration;
      const initializer = declaration.initializer;

      if (!initializer) {
        return;
      }

      const initializerText = initializer.getText();
      const isRequestSource = isUntrustedInputText(initializerText);
      const isTaintedAlias = this.referencesTaintedInput(initializer);

      if (!isRequestSource && !isTaintedAlias) {
        return;
      }

      if (ts.isIdentifier(declaration.name)) {
        this.taintedVariables.add(declaration.name.text);
        return;
      }

      if (ts.isObjectBindingPattern(declaration.name)) {
        declaration.name.elements.forEach((element) => {
          if (ts.isIdentifier(element.name)) {
            this.taintedVariables.add(element.name.text);
          }
        });
      }
    });
  }

  private detectDangerousSinkUsage(): void {
    const callExpressions = ASTVisitor.findNodes(this.sourceFile, (node) => ts.isCallExpression(node));

    callExpressions.forEach((node) => {
      const callExpr = node as ts.CallExpression;
      const sink = this.getDangerousSink(callExpr);

      if (!sink) {
        return;
      }

      const untrustedArgs = callExpr.arguments.filter((arg) => this.referencesTaintedInput(arg));

      if (untrustedArgs.length === 0 || this.hasValidationInContext(callExpr)) {
        return;
      }

      const { line, column } = this.parser.getLineAndColumn(callExpr.getStart());
      const finding: Finding = {
        ruleId: sink.ruleId,
        category: 'VALIDATION',
        severity: sink.severity,
        title: sink.title,
        description: sink.description,
        file: this.filePath,
        line,
        column,
        code: callExpr.getText().substring(0, 120),
        recommendation: sink.recommendation,
      };

      this.generateInjectionPoc(finding, callExpr.getText());
      this.findings.push(finding);
    });
  }

  private getDangerousSink(callExpr: ts.CallExpression): {
    ruleId: string;
    title: string;
    description: string;
    recommendation: string;
    severity: 'CRITICAL' | 'HIGH';
  } | null {
    const localCallName = ASTVisitor.getCallExpressionName(callExpr) || callExpr.expression.getText();
    // Resolve renamed imports — `import { exec as runShell } from 'child_process'`
    // should still match dangerous-API rules even though the local name is `runShell`.
    const resolvedExportedName = resolveCalleeToExportedName(callExpr, this.aliasMap)?.exportedName;
    const callName = resolvedExportedName ?? localCallName;
    // Anchor the SQL-call name to exact dangerous patterns instead of substring matches —
    // avoids "executeMigration", "rawValue", "userQuery" etc.
    const sqlCallNamePattern = /^(query|execute|raw|exec|run|all|get|prepare)$/i;

    // Receiver shape: the object the method is called on must look DB-like. Without
    // this gate, `axios.get(\`https://${host}/...\`)`, `path.get(...)`, `req.query.get(...)`
    // all incorrectly matched as SQL.
    const expr = callExpr.expression;
    const receiverText = ts.isPropertyAccessExpression(expr)
      ? expr.expression.getText(this.sourceFile)
      : '';
    const dbLikeReceiver = /\b(db|database|conn|connection|pool|client|sql|knex|sqlite|pg|postgres|mysql|mariadb|mssql|sequelize|tx|trx|transaction|repo|repository|datasource|prisma)\b/i.test(receiverText);

    // The argument must look like a SQL string: interpolated AND contain SQL keywords
    // (kept from original logic). For template literals, also check the head text.
    const hasInterpolatedQueryArg = callExpr.arguments.some((arg) => {
      if (ts.isTemplateExpression(arg)) {
        const fullText = arg.getText(this.sourceFile);
        return /\b(select|insert|update|delete|from|where|join|having|union)\b/i.test(fullText);
      }
      if (
        ts.isBinaryExpression(arg) &&
        arg.operatorToken.kind === ts.SyntaxKind.PlusToken &&
        /\b(select|insert|update|delete|from|where|join|having)\b/i.test(arg.getText())
      ) {
        return true;
      }
      return false;
    });

    if (sqlCallNamePattern.test(callName) && dbLikeReceiver && hasInterpolatedQueryArg) {
      return {
        ruleId: 'BCR-VAL-001',
        title: 'Unvalidated Input Reaches SQL Query Construction',
        description: 'User-controlled input is interpolated into a raw SQL query. This is directly exploitable for SQL injection when the request value is attacker-controlled.',
        recommendation: 'Use parameterized queries or ORM placeholders. Validate and constrain dynamic field names through a server-side allowlist.',
        severity: 'CRITICAL',
      };
    }

    // Search-helper rule kept but tightened: require the *receiver* to look DB-like.
    // `receiverText` is already computed above.
    if (
      /^search$/i.test(callName) &&
      /\b(db|database|repo|repository|model|query)\b/i.test(receiverText) &&
      callExpr.arguments.some((arg) => /query|filter|term|search/i.test(arg.getText()))
    ) {
      return {
        ruleId: 'BCR-VAL-001',
        title: 'Unvalidated Input Reaches SQL Query Construction',
        description: 'User-controlled search terms reach a backend query-construction helper without a visible allowlist or validation boundary. If the helper builds raw database predicates, this becomes directly exploitable.',
        recommendation: 'Constrain searchable fields and operators through a server-side allowlist, and bind user values through parameterized query APIs instead of dynamic predicate construction.',
        severity: 'CRITICAL',
      };
    }

    // Anchored command-execution call names — no "execute" substring (caught above).
    if (/^(exec|execSync|spawn|spawnSync|fork|execFile|execFileSync)$/i.test(callName)) {
      return {
        ruleId: 'BCR-VAL-002',
        title: 'Unvalidated Input Reaches Command Execution',
        description: 'User-controlled input flows into an operating system command sink. Attackers can inject shell metacharacters and execute arbitrary commands.',
        recommendation: 'Avoid shell invocation with request data. Use safe APIs with fixed arguments and strict allowlists.',
        severity: 'CRITICAL',
      };
    }

    // eval and Function constructor are the genuine dynamic-code sinks.
    // setTimeout/setInterval are only dangerous when the FIRST arg is a string — check arg shape.
    if (/^eval$/i.test(callName) || /^Function$/.test(callName)) {
      return {
        ruleId: 'BCR-VAL-003',
        title: 'Unvalidated Input Reaches Dynamic Code Execution',
        description: 'User-controlled input reaches a dynamic code execution sink. This enables code injection or arbitrary script execution.',
        recommendation: 'Remove dynamic code execution for untrusted data. Parse structured input instead of evaluating it.',
        severity: 'CRITICAL',
      };
    }

    if (/^(setTimeout|setInterval)$/.test(callName)) {
      const first = callExpr.arguments[0];
      // Only flag the string-arg form. Function-arg is the normal usage and not dangerous.
      const isStringForm =
        first &&
        (ts.isStringLiteral(first) ||
          ts.isTemplateExpression(first) ||
          ts.isNoSubstitutionTemplateLiteral(first) ||
          (ts.isBinaryExpression(first) && first.operatorToken.kind === ts.SyntaxKind.PlusToken));
      if (!isStringForm) return null;
      return {
        ruleId: 'BCR-VAL-003',
        title: 'Unvalidated Input Reaches Dynamic Code Execution',
        description: 'User-controlled input reaches a dynamic code execution sink. This enables code injection or arbitrary script execution.',
        recommendation: 'Remove dynamic code execution for untrusted data. Parse structured input instead of evaluating it.',
        severity: 'CRITICAL',
      };
    }

    // Dropped: bare fs-sink detection moved into the dedicated SsrfDetector
    // (BCR-PT-001), which has tighter containment checks and emits a Path-Traversal
    // category rather than the older overlap-prone VALIDATION/BCR-VAL-004 finding.
    // BCR-VAL-004 stays in the rule registry for baseline stability but is no longer
    // emitted — the path-traversal detector covers this surface with fewer FPs.

    return null;
  }


  private referencesTaintedInput(node: ts.Node): boolean {
    if (this.taintTracker?.isTainted(node)) {
      // Cross-check the validated-variables set: if the AST identifier resolves to a
      // declaration the user explicitly passed through joi/yup/zod/etc., respect that.
      const text = node.getText();
      for (const variable of this.validatedVariables) {
        // Treat any direct reference to a validated alias as a detaint signal.
        if (new RegExp(`(^|[^A-Za-z0-9_$])${variable}([^A-Za-z0-9_$]|$)`).test(text)) {
          return false;
        }
      }
      return true;
    }

    return isUntrustedInputText(node.getText());
  }

  /**
   * Checks if validation occurs in the surrounding code context
   * Looks for validation-related keywords and library calls
   *
   * @param node - The AST node to check for validation context
   * @returns true if validation is found in context, false otherwise
   * @private
   */
  private hasValidationInContext(node: ts.Node): boolean {
    return hasValidationBoundary(node, this.sourceFile);
  }

  /**
   * Detects if code contains injection vulnerability patterns
   * and generates POC if vulnerability is found
   *
   * @param finding - The security finding to analyze
   * @param codeContext - The surrounding code context
   * @private
   */
  private generateInjectionPoc(finding: Finding, codeContext: string): void {
    const injectionType = this.detectInjectionType(codeContext);

    if (!injectionType) {
      return;
    }

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

      const result = this.pocGenerator.generate(request);

      if (result.success && result.poc) {
        result.poc.vulnerabilityType = injectionType;
        finding.poc = result.poc;
        finding.injectionType = injectionType;
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.debug('Validation POC generation failed', { error: errorMessage, line: finding.line });
    }
  }

  /**
   * Detects injection vulnerability patterns in code
   *
   * @param code - The code to analyze
   * @returns The injection type (SQL, Command, NoSQL, etc.) or null if not detected
   * @private
   */
  private detectInjectionType(code: string): string | null {
    if (/query|SELECT|INSERT|UPDATE|DELETE|sql|db\.query|db\.execute/i.test(code)) {
      return 'SQL Injection';
    }
    if (/find\(|find\[|\.where|db\.|mongodb|mongoose/i.test(code)) {
      return 'NoSQL Injection';
    }
    if (/exec|spawn|child_process|system|shell|\$\{.*\}.*exec/i.test(code)) {
      return 'Command Injection';
    }
    if (/eval|Function|new Function|vm\.run/i.test(code)) {
      return 'Code Injection';
    }
    if (/template|render|jade|ejs|pug/i.test(code)) {
      return 'Template Injection';
    }

    return null;
  }

  /**
   * Exports POCs from findings to markdown files
   *
   * @param findings - Array of findings with POCs
   * @param outputDir - Directory to save markdown files
   * @returns Array of generated file paths
   */
  exportPocsToMarkdown(findings: Finding[], outputDir: string = './poc-reports'): string[] {
    const fs = require('fs');
    const path = require('path');

    // Create output directory if it doesn't exist
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const generatedFiles: string[] = [];

    findings.forEach((finding, index) => {
      if (!finding.poc) {
        return;
      }

      const poc = finding.poc;
      const fileName = `poc-${finding.injectionType?.replace(/\s+/g, '-').toLowerCase() || 'injection'}-${index + 1}.md`;
      const filePath = path.join(outputDir, fileName);

      const markdown = this.generatePocMarkdown(poc, finding);

      fs.writeFileSync(filePath, markdown, 'utf-8');
      generatedFiles.push(filePath);
    });

    return generatedFiles;
  }

  /**
   * Generates markdown representation of a POC
   *
   * @param poc - The POC to convert to markdown
   * @param finding - The associated finding
   * @returns Markdown string representation
   * @private
   */
  private generatePocMarkdown(poc: ProofOfConcept, finding: Finding): string {
    const lines: string[] = [];

    lines.push(`# ${poc.title}`);
    lines.push('');
    lines.push(`**Severity:** ${this.getSeverityBadge(poc.severity)} ${poc.severity}`);
    lines.push(`**Type:** ${poc.vulnerabilityType}`);
    lines.push(`**CVSS Score:** ${poc.cvssScore ?? 'N/A'}`);
    lines.push(`**OWASP Category:** ${poc.owaspCategory || 'N/A'}`);
    lines.push('');

    lines.push('## Description');
    lines.push(poc.description);
    lines.push('');

    lines.push('## Root Cause');
    lines.push(poc.rootCause);
    lines.push('');

    lines.push('## Vulnerable Code Location');
    lines.push(`- **File:** \`${finding.file}\``);
    lines.push(`- **Line:** ${finding.line}`);
    lines.push(`- **Code:** \`\`\`typescript`);
    lines.push(finding.code);
    lines.push('```');
    lines.push('');

    lines.push('## Exploitation Steps');
    poc.steps.forEach((step) => {
      lines.push(`### Step ${step.stepNumber}: ${step.description}`);
      lines.push(`**Actor:** ${step.actor}`);
      if (step.payload) {
        lines.push(`**Payload:** \`\`\`${step.actionType || 'text'}`);
        lines.push(step.payload);
        lines.push('```');
      }
      if (step.codeSnippet) {
        lines.push(`**Code:**`);
        lines.push('```typescript');
        lines.push(step.codeSnippet);
        lines.push('```');
      }
      if (step.expectedResult) {
        lines.push(`**Expected Result:** ${step.expectedResult}`);
      }
      lines.push('');
    });

    lines.push('## Attack Payloads');
    poc.payloads.forEach((payload) => {
      lines.push(`### ${payload.name}`);
      lines.push(`**Type:** ${payload.contentType}`);
      lines.push(`**Difficulty:** ${payload.difficulty || 'N/A'}`);
      lines.push(`**Success Rate:** ${payload.successRate || 'N/A'}%`);
      lines.push('');
      lines.push(`**Description:** ${payload.description}`);
      lines.push('');
      lines.push('**Payload:**');
      lines.push('```');
      lines.push(payload.content);
      lines.push('```');
      if (payload.expectedOutput) {
        lines.push(`**Expected Output:** ${payload.expectedOutput}`);
      }
      lines.push('');
    });

    lines.push('## Business Impact');
    lines.push(poc.businessImpact);
    lines.push('');

    lines.push('## Technical Impact');
    lines.push(poc.technicalImpact);
    lines.push('');

    if (poc.preconditions && poc.preconditions.length > 0) {
      lines.push('## Preconditions');
      poc.preconditions.forEach((condition) => {
        lines.push(`- ${condition}`);
      });
      lines.push('');
    }

    lines.push('## Remediation');
    lines.push(poc.remediationDescription);
    lines.push('');

    if (poc.remediationCode) {
      lines.push('### Remediation Code');
      lines.push('```typescript');
      lines.push(poc.remediationCode);
      lines.push('```');
      lines.push('');
    }

    lines.push('## Code Flow');
    lines.push(poc.codeFlow.diagram);
    lines.push('');

    lines.push('---');
    lines.push(`Generated: ${poc.generatedAt.toISOString()}`);
    lines.push(`POC Version: ${poc.pocVersion}`);

    return lines.join('\n');
  }

  /**
   * Get severity badge/emoji for reports
   *
   * @param severity - The severity level
   * @returns Emoji badge for the severity
   * @private
   */
  private getSeverityBadge(severity: string): string {
    const badges: { [key: string]: string } = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🟢',
      INFO: '🔵',
    };
    return badges[severity] || '⚪';
  }

  /**
   * Get POCs from findings that have injection vulnerabilities
   *
   * @returns Array of POCs from findings
   */
  getGeneratedPocs(): ProofOfConcept[] {
    return this.findings
      .filter((f) => f.poc)
      .map((f) => f.poc as ProofOfConcept);
  }
}
