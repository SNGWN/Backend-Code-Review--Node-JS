/**
 * Rule-ID-pinned coverage tests.
 *
 * The test-coverage audit found that only 8 of the 60+ rules had direct ruleId
 * assertions. Other rules were tested via title or category which is fragile under
 * detector tweaks. This file pins ruleId expectations for the highest-impact rules
 * the audit flagged as untested.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

function tmpFixture(name: string, content: string): string {
  const filePath = path.join(os.tmpdir(), `bcr-ridcov-${Date.now()}-${Math.random().toString(36).slice(2)}-${name}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

describe('Rule-ID pinned coverage', () => {
  test('BCR-MA-001 fires on Object.assign(target, req.body) [regression for qualified-name match bug]', () => {
    // Object.assign matching was previously broken — findCallExpressions(name='Object.assign')
    // matched only the property name (`assign`), so BCR-MA-001 silently never fired.
    const filePath = tmpFixture('ma-001.ts', `
      import express from 'express';
      const app = express();
      app.post('/api/users', (req, res) => {
        const user = {};
        Object.assign(user, req.body);
        res.json(user);
      });
      export default app;
    `);
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    const found = report.findings.find((f) => f.ruleId === 'BCR-MA-001');
    expect(found).toBeDefined();
    expect(found?.severity).toBe('CRITICAL');
  });

  test('BCR-VAL-004 is deprecated and never emitted', () => {
    const filePath = tmpFixture('val-004.ts', `
      import { readFileSync } from 'fs';
      import express from 'express';
      const app = express();
      app.get('/api/file', (req, res) => {
        const name = String(req.query.name);
        const buf = readFileSync(name);
        res.send(buf);
      });
      export default app;
    `);
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    // BCR-VAL-004 used to fire here; it's now subsumed by BCR-PT-001 with better precision.
    expect(report.findings.find((f) => f.ruleId === 'BCR-VAL-004')).toBeUndefined();
    expect(report.findings.find((f) => f.ruleId === 'BCR-PT-001')).toBeDefined();
  });

  test('BCR-JWT-004 fires on HS256 + publicKey (key confusion)', () => {
    const filePath = tmpFixture('jwt-004.ts', `
      import jwt from 'jsonwebtoken';
      const publicKey = '-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----';
      function bad(token: string) {
        return jwt.verify(token, publicKey, { algorithms: ['HS256'] });
      }
      void bad;
    `);
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    expect(report.findings.find((f) => f.ruleId === 'BCR-JWT-004')).toBeDefined();
  });

  test('BCR-JWT-006 fires on ignoreExpiration: true', () => {
    const filePath = tmpFixture('jwt-006.ts', `
      import jwt from 'jsonwebtoken';
      function bad(token: string, secret: string) {
        return jwt.verify(token, secret, { algorithms: ['HS256'], ignoreExpiration: true });
      }
      void bad;
    `);
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    expect(report.findings.find((f) => f.ruleId === 'BCR-JWT-006')).toBeDefined();
  });

  test('BCR-MA-005 fires on { constructor: ... } property assignment', () => {
    const filePath = tmpFixture('ma-005.ts', `
      const evil = { constructor: { prototype: {} } };
      export { evil };
    `);
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    expect(report.findings.find((f) => f.ruleId === 'BCR-MA-005')).toBeDefined();
  });
});

describe('Edge cases (parser/scanner robustness)', () => {
  test('empty source file produces zero findings and no runtime error', () => {
    const filePath = tmpFixture('empty.ts', '');
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    expect(report.totalFindings).toBe(0);
    expect(report.hasRuntimeErrors).toBe(false);
  });

  test('comments-only source produces zero findings', () => {
    const filePath = tmpFixture('comments-only.ts', '// just a comment\n/* and a block */\n');
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    expect(report.totalFindings).toBe(0);
  });

  test('imports-only file does not crash alias resolver', () => {
    const filePath = tmpFixture('imports-only.ts', "import { exec } from 'child_process';\nvoid exec;\n");
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    expect(report.totalFindings).toBe(0);
    expect(report.hasRuntimeErrors).toBe(false);
  });

  test('CRLF line endings work for inline suppression', () => {
    const filePath = tmpFixture('crlf.ts', [
      "import express from 'express';",
      'const app = express();',
      '// bcr-disable-next-line BCR-AUTH-002 -- triaged',
      "const JWT_SECRET = 'k7Hf91p2QvX8r4Lc2NaB3Tg5Y6Wm0Eu9';",
      'void JWT_SECRET;',
      'export default app;',
    ].join('\r\n'));
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    // The hardcoded secret on the next line should be suppressed inline.
    const hardcoded = report.findings.find((f) => f.ruleId === 'BCR-AUTH-002' && f.line === 4);
    expect(hardcoded).toBeUndefined();
  });

  test('large synthetic file (5000 trivial statements) analyzes in under 5 seconds', () => {
    const lines: string[] = [];
    for (let i = 0; i < 5000; i++) {
      lines.push(`const x${i} = ${i};`);
    }
    const filePath = tmpFixture('large.ts', lines.join('\n'));
    const start = Date.now();
    const report = new BackendCodeReviewAnalyzer().analyze(filePath);
    const elapsed = Date.now() - start;
    expect(report.totalFindings).toBe(0);
    expect(elapsed).toBeLessThan(5000);
  });
});
