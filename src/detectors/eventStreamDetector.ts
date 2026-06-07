import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';

/**
 * Event Stream Injection Detector
 *
 * Detects event-driven architecture vulnerabilities:
 * - Injecting malicious event payloads
 * - Event handler bypass via crafted events
 * - Cross-tenant event leakage
 * - Event data not properly sanitized before processing
 */
export class EventStreamDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;

  constructor(filePath: string, sourceFile: ts.SourceFile, _parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
  }

  detect(): DetectorResult {
    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isCallExpression(node)) {
        this.checkEventInjection(node);
        this.checkTenantIsolation(node);
      }
    });
    return { findings: this.findings };
  }

  private checkEventInjection(node: ts.CallExpression): void {
    const sourceText = node.getText(this.sourceFile);
    const eventHandlerCall = /\.on\(|\.addEventListener|\.subscribe|EventEmitter|event\.subscribe|pub\.on/i.test(
      sourceText
    );
    const userControlledData = /req\.(body|query|params|headers)|request\.(body|query|params|headers)/i.test(
      sourceText
    );
    const hasValidation = /validate|sanitize|escape|filter|schema|joi|yup|zod/i.test(sourceText);

    if (eventHandlerCall && userControlledData && !hasValidation) {
      const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      this.findings.push({
        file: this.filePath,
        line: lineNum,
        column: 0,
        ruleId: 'BCR-EVT-001',
        severity: 'HIGH',
        category: 'EVENT_STREAM',
        title: 'Exploitable Event Handler Injection via Untrusted Payload',
        description:
          'Event handler consumes attacker-controlled data without validation, enabling event-driven injection chains.',
        code: sourceText,
        recommendation:
          'Enforce schema validation on all event payloads before handler execution and reject untrusted fields.',
      });
    }

    const calleeText = node.expression.getText(this.sourceFile).toLowerCase();
    const dynamicEventPublish =
      calleeText.includes('.emit') ||
      calleeText.includes('.fire') ||
      calleeText.includes('eventbus.publish') ||
      calleeText.includes('eventemitter.publish');
    const eventNameArg = node.arguments[0]?.getText(this.sourceFile) || '';
    const userControlledEventName = /req\.(query|params|body)|request\.(query|params|body)|user\./i.test(
      eventNameArg
    );
    if (dynamicEventPublish && userControlledEventName) {
      const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      this.findings.push({
        file: this.filePath,
        line: lineNum,
        column: 0,
        ruleId: 'BCR-EVT-002',
        severity: 'HIGH',
        category: 'EVENT_STREAM',
        title: 'User-Controlled Event Name Enables Handler Abuse',
        description:
          'Event name/type is attacker-controlled, enabling unauthorized handler triggering and chainable workflow abuse.',
        code: sourceText,
        recommendation:
          'Use strict allowlisted event names and map user input to internal constants rather than direct emission.',
      });
    }
  }

  private checkTenantIsolation(node: ts.CallExpression): void {
    // Require a real event-handler registration on an emitter/socket-like receiver, and a handler
    // that actually performs a DB operation on sensitive-domain data without tenant scoping.
    // The previous version fired on any `.on(...)` whose text merely contained a domain word.
    const callee = node.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const method = callee.name.text.toLowerCase();
    if (!/^(on|once|subscribe|addlistener)$/.test(method)) return;
    const receiver = callee.expression.getText(this.sourceFile).toLowerCase();
    if (!/\b(socket|io|emitter|eventemitter|bus|eventbus|stream|channel|subscriber|pubsub|ws|wss|connection|conn)\b/.test(receiver)) {
      return;
    }

    const handlerArg = node.arguments[node.arguments.length - 1];
    let handlerText = '';
    if (handlerArg && (ts.isArrowFunction(handlerArg) || ts.isFunctionExpression(handlerArg))) {
      handlerText = handlerArg.getText(this.sourceFile);
    } else if (handlerArg && ts.isIdentifier(handlerArg)) {
      const fn =
        ASTVisitor.findFunctionDeclarations(this.sourceFile, handlerArg.text)[0] ??
        ASTVisitor.findVariableDeclarations(this.sourceFile, handlerArg.text).find(
          (d) => d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))
        )?.initializer;
      handlerText = fn ? fn.getText(this.sourceFile) : '';
    }
    if (!handlerText) return;

    const sensitiveDataOp =
      /\b(db|database|model|models|repo|repository|prisma|knex|sequelize|collection)\b\s*\.\s*\w/i.test(handlerText) &&
      /\b(user|account|profile|order|payment|billing|invoice|wallet|balance|transaction)\b/i.test(handlerText);
    const hasTenantScope = /\b(tenantId|tenant|orgId|organisation|organization|workspace|accountId|ownerId|scope)\b/i.test(handlerText);
    if (!sensitiveDataOp || hasTenantScope) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      ruleId: 'BCR-EVT-003',
      severity: 'HIGH',
      confidence: 'TENTATIVE',
      verify: 'Confirm this event handler reads/writes another tenant’s data without an org/tenant scope.',
      category: 'EVENT_STREAM',
      title: 'Missing Tenant Scoping in Sensitive Event Handler',
      description:
        'Sensitive event handling appears unscoped by tenant/account context, which can enable cross-tenant event abuse.',
      code: node.getText(this.sourceFile).substring(0, 120),
      recommendation:
        'Bind event channels and handler authorization checks to tenant/account context before processing.',
    });
  }
}
