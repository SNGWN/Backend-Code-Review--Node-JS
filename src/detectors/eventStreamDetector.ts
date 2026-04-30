import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';

/**
 * Event Stream Injection Detector (Phase 3)
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
  private parser: ASTParser;

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
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
    const sourceText = node.getText(this.sourceFile);

    const eventHandlerCall = /\.on\(|\.subscribe|EventEmitter|event\.on/.test(sourceText);
    const likelySensitiveDomain = /user|account|profile|order|payment|billing|invoice/i.test(sourceText);
    const hasTenantScope = /tenantId|tenant|org|workspace|accountId|scope/i.test(sourceText);

    if (!eventHandlerCall || !likelySensitiveDomain || hasTenantScope) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      severity: 'HIGH',
      category: 'EVENT_STREAM',
      title: 'Missing Tenant Scoping in Sensitive Event Handler',
      description:
        'Sensitive event handling appears unscoped by tenant/account context, which can enable cross-tenant event abuse.',
      code: sourceText,
      recommendation:
        'Bind event channels and handler authorization checks to tenant/account context before processing.',
    });
  }
}
