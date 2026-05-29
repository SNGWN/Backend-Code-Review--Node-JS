import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';

/**
 * Message Queue Vulnerability Detector
 *
 * Detects message queue exploitation patterns:
 * - Unvalidated deserialization of queue messages
 * - Queue message tampering without verification
 * - Missing authentication/authorization on queue operations
 * - Replay attacks via queue messages
 */
export class MessageQueueDetector {
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
        this.checkUnvalidatedDeserialization(node);
        this.checkMissingQueueAuth(node);
        this.checkMessageTampering(node);
      }
    });
    return { findings: this.findings };
  }

  private checkUnvalidatedDeserialization(node: ts.CallExpression): void {
    const sourceText = node.getText(this.sourceFile);

    const queueConsumerCall = /\.on\(|\.consume|\.subscribe|\.listen/.test(sourceText);
    const unsafeDeserializer = /JSON\.parse|eval|new\s+Function/.test(sourceText);
    const messageBodySource = /msg|message|payload|body/.test(sourceText);
    const hasValidation = /validate|verify|schema|joi|yup|zod/.test(sourceText);

    if (!queueConsumerCall || !unsafeDeserializer || !messageBodySource || hasValidation) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      ruleId: 'BCR-MQ-001',
      severity: 'CRITICAL',
      category: 'MESSAGE_QUEUE',
      title: 'Exploitable Queue Consumer Deserialization',
      description:
        'Queue consumer deserializes attacker-controllable message content without schema validation, which can be chained into code or object-manipulation attacks.',
      code: sourceText,
      recommendation:
        'Validate queue payloads against strict schemas before deserialization and reject messages that do not pass integrity and structure checks.',
    });
  }

  private checkMissingQueueAuth(node: ts.CallExpression): void {
    const sourceText = node.getText(this.sourceFile);

    const publishCall = /\.publish|\.send|\.push|\.enqueue/.test(sourceText);
    const userControlledPayload = /req\.(body|query|params)|request\.(body|query|params)/i.test(sourceText);
    const hasAuthControl = /auth|verify|token|signature|hmac|sign/i.test(sourceText);

    if (!publishCall || !userControlledPayload || hasAuthControl) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      ruleId: 'BCR-MQ-002',
      severity: 'HIGH',
      category: 'MESSAGE_QUEUE',
      title: 'Unsigned Queue Publish with User-Controlled Payload',
      description:
        'Queue publish operation sends attacker-controlled payloads without authenticity controls, enabling forged message injection and downstream attack chains.',
      code: sourceText,
      recommendation:
        'Sign outbound queue messages (HMAC/signature) and enforce signature verification in all consumers.',
    });
  }

  private checkMessageTampering(node: ts.CallExpression): void {
    const sourceText = node.getText(this.sourceFile);

    const brokerAckFlow = /amqp|kafka|sqs|rabbitmq/i.test(sourceText) && /\.ack|\.nack|\.nak/.test(sourceText);
    const touchesMessage = /msg|message|payload/.test(sourceText);
    const hasIntegrityCheck = /signature|hmac|verify|checksum/.test(sourceText);

    if (!brokerAckFlow || !touchesMessage || hasIntegrityCheck) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      ruleId: 'BCR-MQ-003',
      severity: 'HIGH',
      category: 'MESSAGE_QUEUE',
      title: 'Queue Message Integrity Not Verified Before Ack',
      description:
        'Queue message handling acknowledges broker messages without integrity verification, enabling tampered message replay/injection chains.',
      code: sourceText,
      recommendation:
        'Verify message integrity (HMAC/signature/checksum) prior to processing and acknowledgment.',
    });
  }
}
