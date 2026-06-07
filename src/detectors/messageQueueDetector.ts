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
    // Operate on the consumer REGISTRATION call and inspect its handler — including a decoupled
    // named handler (`channel.consume(q, handleMessage)`), which the previous inline-only text
    // match could never see.
    const callee = node.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const method = callee.name.text.toLowerCase();
    if (!/^(on|once|consume|subscribe|listen|process|eachmessage|eachbatch|handle|receive)$/.test(method)) return;

    const handlerBody = this.resolveHandlerBody(node.arguments[node.arguments.length - 1]);
    if (!handlerBody) return;

    const unsafeDeserializer = /JSON\.parse|eval\(|new\s+Function|\bdeserialize\b|\bunserialize\b|node-serialize/.test(handlerBody);
    const messageBodySource = /\b(msg|message|payload|body|data|record|content|value|event)\b/.test(handlerBody);
    const hasValidation = /\b(validate|verify|schema|joi|yup|zod|ajv|safeParse|parseAsync)\b/i.test(handlerBody);

    if (!unsafeDeserializer || !messageBodySource || hasValidation) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      ruleId: 'BCR-MQ-001',
      severity: 'CRITICAL',
      confidence: 'FIRM',
      verify: 'Confirm the message payload is deserialized without a prior schema/signature check in the handler.',
      category: 'MESSAGE_QUEUE',
      title: 'Exploitable Queue Consumer Deserialization',
      description:
        'Queue consumer deserializes attacker-controllable message content without schema validation, which can be chained into code or object-manipulation attacks.',
      code: node.getText(this.sourceFile).substring(0, 120),
      recommendation:
        'Validate queue payloads against strict schemas before deserialization and reject messages that do not pass integrity and structure checks.',
    });
  }

  /** Returns the body text of a handler argument: an inline arrow/function, or a resolved named function. */
  private resolveHandlerBody(handler: ts.Expression | undefined): string {
    if (!handler) return '';
    if (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler)) {
      return handler.getText(this.sourceFile);
    }
    if (ts.isIdentifier(handler)) {
      const fn =
        ASTVisitor.findFunctionDeclarations(this.sourceFile, handler.text)[0] ??
        ASTVisitor.findVariableDeclarations(this.sourceFile, handler.text).find(
          (d) => d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer))
        )?.initializer;
      return fn ? fn.getText(this.sourceFile) : '';
    }
    return '';
  }

  private checkMissingQueueAuth(node: ts.CallExpression): void {
    // Gate on a queue/broker-like RECEIVER so `Array.push(...)` and `res.send(...)` no longer
    // false-positive as queue publishes (the previous `/\.push|\.send/` text match did).
    const callee = node.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const method = callee.name.text.toLowerCase();
    if (!/^(publish|send|sendmessage|sendtoqueue|enqueue|produce|emit)$/.test(method)) return;
    const receiver = callee.expression.getText(this.sourceFile).toLowerCase();
    const isQueueReceiver = /\b(queue|channel|producer|topic|exchange|kafka|sqs|sns|rabbit|amqp|broker|bus|stream|pubsub|publisher|mq|nats|bull|kue|jetstream|eventbridge)\b/.test(receiver);
    if (!isQueueReceiver) return;

    const sourceText = node.getText(this.sourceFile);
    const userControlledPayload = /\b(req|request)\.(body|query|params)\b/i.test(sourceText);
    const hasAuthControl = /\b(auth|verify|token|signature|hmac|sign)\b/i.test(sourceText);

    if (!userControlledPayload || hasAuthControl) {
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
