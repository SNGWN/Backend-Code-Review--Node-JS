import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { Finding } from '../src/types';

/**
 * Coverage for the exploitable-class detectors added in the comprehensive review:
 * NoSQL injection, SSTI, XXE, ORM raw SQL, weak-hash createHash, env-fallback secrets,
 * reflected-origin CORS with credentials, and dynamic prototype pollution.
 */
let counter = 0;
function scan(name: string, content: string): Finding[] {
  counter += 1;
  const filePath = path.join(os.tmpdir(), `bcr-newdet-${process.pid}-${counter}-${name}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  const report = new BackendCodeReviewAnalyzer().analyze(filePath, {
    includeHeuristics: true,
    minSeverity: 'LOW',
  });
  return report.findings;
}

const has = (findings: Finding[], ruleId: string): boolean =>
  findings.some((f) => f.ruleId === ruleId);

describe('New exploitable-class detectors', () => {
  test('BCR-VAL-013 fires on a NoSQL operator-injection filter', () => {
    const f = scan('nosql.ts', `
      declare const User: any;
      export async function h(req: any) {
        return User.find({ name: req.query.name });
      }
    `);
    expect(has(f, 'BCR-VAL-013')).toBe(true);
  });

  test('BCR-VAL-013 does NOT fire when the value is coerced to a string', () => {
    const f = scan('nosql-safe.ts', `
      declare const User: any;
      export async function h(req: any) {
        return User.find({ name: String(req.query.name) });
      }
    `);
    expect(has(f, 'BCR-VAL-013')).toBe(false);
  });

  test('BCR-VAL-013 flags $where server-side JavaScript as CRITICAL', () => {
    const f = scan('nosql-where.ts', `
      declare const Account: any;
      export async function h(req: any) {
        return Account.find({ $where: 'this.x == ' + req.body.x });
      }
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-VAL-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  test('BCR-VAL-014 fires on template compilation from user input (SSTI)', () => {
    const f = scan('ssti.ts', `
      declare const handlebars: any;
      export function h(req: any) {
        return handlebars.compile(req.body.template);
      }
    `);
    expect(has(f, 'BCR-VAL-014')).toBe(true);
  });

  test('BCR-VAL-015 fires when XML parsing enables external entities', () => {
    const f = scan('xxe.ts', `
      declare const libxml: any;
      export function h(req: any) {
        return libxml.parseXml(req.body.xml, { noent: true });
      }
    `);
    expect(has(f, 'BCR-VAL-015')).toBe(true);
  });

  test('BCR-VAL-001 fires on a query-builder raw concatenation (whereRaw)', () => {
    const f = scan('ormraw.ts', `
      declare const knex: any;
      export async function h(req: any) {
        return knex.whereRaw('age > ' + req.query.age);
      }
    `);
    expect(has(f, 'BCR-VAL-001')).toBe(true);
  });

  test('BCR-CRYPTO-001 fires on crypto.createHash("md5") in a security context', () => {
    const f = scan('md5.ts', `
      import * as crypto from 'crypto';
      export function signToken(token: string) {
        return crypto.createHash('md5').update(token).digest('hex');
      }
    `);
    expect(has(f, 'BCR-CRYPTO-001')).toBe(true);
  });

  test('BCR-KEY-008 fires on a secret env var with a hardcoded fallback', () => {
    const f = scan('envfallback.ts', `
      export const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-fallback';
    `);
    expect(has(f, 'BCR-KEY-008')).toBe(true);
  });

  test('BCR-MISC-005 fires on a CORS callback that unconditionally allows with credentials', () => {
    const f = scan('cors.ts', `
      import cors from 'cors';
      export const mw = cors({ origin: (origin, cb) => cb(null, true), credentials: true });
    `);
    expect(has(f, 'BCR-MISC-005')).toBe(true);
  });

  test('BCR-MISC-005 does NOT fire on an allowlist CORS callback', () => {
    const f = scan('cors-safe.ts', `
      import cors from 'cors';
      const allow = ['https://a.com'];
      export const mw = cors({ origin: (o: string, cb: any) => cb(null, allow.includes(o)), credentials: true });
    `);
    expect(has(f, 'BCR-MISC-005')).toBe(false);
  });

  test('BCR-MA-007 fires on a dynamic user-controlled property assignment', () => {
    const f = scan('proto.ts', `
      export function h(req: any) {
        const target: any = {};
        target[req.body.key] = req.body.value;
        return target;
      }
    `);
    expect(has(f, 'BCR-MA-007')).toBe(true);
  });

  test('BCR-JWT-009 fires on jwt.sign without an expiry (TENTATIVE)', () => {
    const f = scan('jwtnoexp.ts', `
      import jwt from 'jsonwebtoken';
      export function issue(user: any) {
        return jwt.sign({ sub: user.id }, 'secret');
      }
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-JWT-009');
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('TENTATIVE');
  });

  test('BCR-JWT-009 does NOT fire when expiresIn is set', () => {
    const f = scan('jwtexp.ts', `
      import jwt from 'jsonwebtoken';
      export function issue(user: any) {
        return jwt.sign({ sub: user.id }, 'secret', { expiresIn: '15m' });
      }
    `);
    expect(has(f, 'BCR-JWT-009')).toBe(false);
  });

  test('BCR-CRYPTO-006 fires on a timing-unsafe signature comparison', () => {
    const f = scan('timing.ts', `
      import * as crypto from 'crypto';
      export function verifyHook(sigHeader: string, body: string) {
        const expectedSignature = crypto.createHmac('sha256', 'k').update(body).digest('hex');
        return sigHeader === expectedSignature;
      }
    `);
    expect(has(f, 'BCR-CRYPTO-006')).toBe(true);
  });

  test('BCR-AC-002 generalises beyond the three hardcoded id names (accountId)', () => {
    const f = scan('bola.ts', `
      import express from 'express';
      const app = express();
      app.get('/x', (req: any, res: any) => {
        const accountId = req.params.accountId;
        const acct = db.findOne({ id: accountId });
        res.json(acct);
      });
      export default app;
    `);
    expect(has(f, 'BCR-AC-002')).toBe(true);
  });
});
