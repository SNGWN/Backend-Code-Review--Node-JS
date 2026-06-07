import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { Finding } from '../src/types';

/**
 * Framework-aware taint: controller decorators (NestJS), message-queue / event consumer
 * payloads, and GraphQL resolver args are attacker-controlled entry points, and one-way
 * transforms (hash/encrypt) must not propagate injection taint to their output.
 */
let counter = 0;
function scan(name: string, content: string): Finding[] {
  counter += 1;
  const filePath = path.join(os.tmpdir(), `bcr-fw-${process.pid}-${counter}-${name}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  return new BackendCodeReviewAnalyzer()
    .analyze(filePath, { includeHeuristics: true, minSeverity: 'LOW' })
    .findings;
}
const hasSql = (f: Finding[]): boolean => f.some((x) => /SQL/i.test(x.title));

describe('Framework-aware taint sources', () => {
  test('NestJS @Body() parameter is a taint source reaching a SQL sink', () => {
    const f = scan('nest.ts', `
      import { Controller, Post, Body } from '@nestjs/common';
      declare const db: any;
      @Controller('users')
      export class UsersController {
        @Post()
        create(@Body() dto: any) {
          db.query('INSERT INTO users VALUES (' + dto.name + ')');
        }
      }
    `);
    expect(hasSql(f)).toBe(true);
  });

  test('message-queue consumer payload is a taint source', () => {
    const f = scan('mq.ts', `
      declare const channel: any;
      declare const db: any;
      export function consume() {
        channel.consume('q', (msg: any) => {
          db.query('SELECT * FROM t WHERE k = ' + msg.content.toString());
        });
      }
    `);
    expect(hasSql(f)).toBe(true);
  });

  test('one-way hash of tainted input does NOT propagate injection taint', () => {
    const f = scan('oneway.ts', `
      import * as crypto from 'crypto';
      declare const db: any;
      export function h(req: any) {
        const digest = crypto.createHash('sha256').update(req.body.x).digest('hex');
        db.query('SELECT * FROM t WHERE k = ' + digest);
      }
    `);
    expect(hasSql(f)).toBe(false);
  });
});
