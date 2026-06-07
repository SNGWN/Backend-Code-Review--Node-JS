import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { Finding } from '../src/types';

/**
 * Locks the false-positive reductions from the detector precision pass: infra detectors keyed on
 * the actual sink call (not enclosing text), message-queue publish gated on a queue receiver, and
 * event-stream tenant-scoping gated on a real emitter + DB op.
 */
let counter = 0;
function scan(name: string, content: string): Finding[] {
  counter += 1;
  const filePath = path.join(os.tmpdir(), `bcr-prec-${process.pid}-${counter}-${name}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  return new BackendCodeReviewAnalyzer()
    .analyze(filePath, { includeHeuristics: true, minSeverity: 'LOW' })
    .findings;
}
const count = (f: Finding[], ruleId: string): number => f.filter((x) => x.ruleId === ruleId).length;

describe('Detector precision (FP reductions)', () => {
  test('MQ publish rule does NOT fire on res.send / Array.push of user data', () => {
    const f = scan('mqfp.ts', `
      export function h(req: any, res: any) {
        const items: any[] = [];
        items.push(req.body.item);
        res.send(req.body);
      }
    `);
    expect(count(f, 'BCR-MQ-002')).toBe(0);
  });

  test('MQ publish rule DOES fire on a real queue publish of user data', () => {
    const f = scan('mqtrue.ts', `
      declare const queue: any;
      export function h(req: any) {
        queue.publish('orders', req.body);
      }
    `);
    expect(count(f, 'BCR-MQ-002')).toBeGreaterThan(0);
  });

  test('cache poisoning is reported once (no outer-route + inner-sink double report)', () => {
    const f = scan('cachedup.ts', `
      import express from 'express';
      const app = express();
      declare const cache: any;
      app.get('/x', (req: any, res: any) => {
        cache.set(req.headers.host, res);
      });
      export default app;
    `);
    expect(count(f, 'BCR-CACHE-002') + count(f, 'BCR-CACHE-001')).toBe(1);
  });

  test('event-stream tenant rule does NOT fire on a plain emitter handler mentioning a domain word', () => {
    const f = scan('evtfp.ts', `
      declare const emitter: any;
      emitter.on('userJoined', (data: any) => {
        console.log('user joined', data.id);
      });
    `);
    expect(count(f, 'BCR-EVT-003')).toBe(0);
  });
});
