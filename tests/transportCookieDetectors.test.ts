import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { Finding } from '../src/types';

/**
 * Coverage for the insecure-transport (TLS) and cookie-security detectors.
 */
let counter = 0;
const createdFiles: string[] = [];
function scan(name: string, content: string): Finding[] {
  counter += 1;
  const filePath = path.join(os.tmpdir(), `bcr-tlscookie-${process.pid}-${counter}-${name}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  createdFiles.push(filePath);
  const report = new BackendCodeReviewAnalyzer().analyze(filePath, {
    includeHeuristics: true,
    minSeverity: 'LOW',
  });
  return report.findings;
}

// Don't leave bcr-tlscookie-* temp files behind — they accumulate in the OS temp dir
// across runs and can pollute CI environments.
afterAll(() => {
  for (const file of createdFiles) {
    try {
      fs.unlinkSync(file);
    } catch {
      /* already gone — ignore */
    }
  }
});

const has = (findings: Finding[], ruleId: string): boolean =>
  findings.some((f) => f.ruleId === ruleId);

describe('InsecureTransportDetector', () => {
  test('BCR-TLS-001 fires on rejectUnauthorized: false in an https agent', () => {
    const f = scan('tls-agent.ts', `
      import https from 'https';
      export const agent = new https.Agent({ rejectUnauthorized: false });
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-TLS-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  test('BCR-TLS-001 fires on an axios request with rejectUnauthorized: false', () => {
    const f = scan('tls-axios.ts', `
      import axios from 'axios';
      import https from 'https';
      export const call = () => axios.get('https://api.example.com', {
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      });
    `);
    expect(has(f, 'BCR-TLS-001')).toBe(true);
  });

  test('BCR-TLS-001 fires on the falsy numeric variant rejectUnauthorized: 0', () => {
    const f = scan('tls-zero.ts', `
      import tls from 'tls';
      export const s = tls.connect({ host: 'h', rejectUnauthorized: 0 });
    `);
    expect(has(f, 'BCR-TLS-001')).toBe(true);
  });

  test('BCR-TLS-001 does NOT fire when rejectUnauthorized is a non-literal (e.g. isProd)', () => {
    const f = scan('tls-dynamic.ts', `
      import https from 'https';
      declare const isProd: boolean;
      export const agent = new https.Agent({ rejectUnauthorized: isProd });
    `);
    expect(has(f, 'BCR-TLS-001')).toBe(false);
  });

  test('BCR-TLS-001 does NOT fire when rejectUnauthorized is true', () => {
    const f = scan('tls-safe.ts', `
      import https from 'https';
      export const agent = new https.Agent({ rejectUnauthorized: true });
    `);
    expect(has(f, 'BCR-TLS-001')).toBe(false);
  });

  test('BCR-TLS-002 fires on NODE_TLS_REJECT_UNAUTHORIZED = "0"', () => {
    const f = scan('tls-env.ts', `
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-TLS-002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  test('BCR-TLS-002 fires on bracket-access env assignment', () => {
    const f = scan('tls-env-bracket.ts', `
      process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = "0";
    `);
    expect(has(f, 'BCR-TLS-002')).toBe(true);
  });

  test('BCR-TLS-002 does NOT fire when the value is "1"', () => {
    const f = scan('tls-env-on.ts', `
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
    `);
    expect(has(f, 'BCR-TLS-002')).toBe(false);
  });
});

describe('CookieSecurityDetector', () => {
  test('BCR-COOKIE-001 fires on res.cookie with httpOnly: false', () => {
    const f = scan('cookie-httponly-false.ts', `
      export function login(req: any, res: any) {
        res.cookie('session', 'abc', { httpOnly: false, secure: true, sameSite: 'lax' });
      }
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-COOKIE-001');
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('FIRM');
  });

  test('BCR-COOKIE-001 fires on a session cookie set with no options (insecure default)', () => {
    const f = scan('cookie-default.ts', `
      export function login(req: any, res: any) {
        res.cookie('auth_token', 'abc');
      }
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-COOKIE-001');
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('TENTATIVE');
  });

  test('BCR-COOKIE-001 does NOT fire when httpOnly: true', () => {
    const f = scan('cookie-safe.ts', `
      export function login(req: any, res: any) {
        res.cookie('session', 'abc', { httpOnly: true, secure: true, sameSite: 'strict' });
      }
    `);
    expect(has(f, 'BCR-COOKIE-001')).toBe(false);
  });

  test('BCR-COOKIE-001 does NOT fire on a non-sensitive cookie left at default', () => {
    const f = scan('cookie-nonsensitive.ts', `
      export function setTheme(req: any, res: any) {
        res.cookie('theme', 'dark');
      }
    `);
    expect(has(f, 'BCR-COOKIE-001')).toBe(false);
  });

  test('BCR-COOKIE-002 fires when a session cookie omits secure', () => {
    const f = scan('cookie-nosecure.ts', `
      export function login(req: any, res: any) {
        res.cookie('session', 'abc', { httpOnly: true });
      }
    `);
    expect(has(f, 'BCR-COOKIE-002')).toBe(true);
  });

  test('a dynamically-named cookie with no options does NOT fire (no false positive)', () => {
    const f = scan('cookie-dynamic.ts', `
      export function set(req: any, res: any, name: string) {
        res.cookie(name, 'abc');
      }
    `);
    expect(has(f, 'BCR-COOKIE-001')).toBe(false);
    expect(has(f, 'BCR-COOKIE-002')).toBe(false);
    expect(has(f, 'BCR-COOKIE-003')).toBe(false);
  });

  test('a dynamically-named cookie with explicit httpOnly: false still fires', () => {
    const f = scan('cookie-dynamic-false.ts', `
      export function set(req: any, res: any, name: string) {
        res.cookie(name, 'abc', { httpOnly: false });
      }
    `);
    expect(has(f, 'BCR-COOKIE-001')).toBe(true);
  });

  test('sameSite: false is treated as absent (TENTATIVE), not none (FIRM)', () => {
    const f = scan('cookie-samesite-false.ts', `
      export function login(req: any, res: any) {
        res.cookie('session', 'abc', { httpOnly: true, secure: true, sameSite: false });
      }
    `);
    const finding = f.find((x) => x.ruleId === 'BCR-COOKIE-003');
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('TENTATIVE');
    expect(finding?.description).toMatch(/without a .sameSite. attribute/i);
  });

  test('BCR-COOKIE-003 fires on sameSite: none', () => {
    const f = scan('cookie-samesite-none.ts', `
      export function login(req: any, res: any) {
        res.cookie('session', 'abc', { httpOnly: true, secure: true, sameSite: 'none' });
      }
    `);
    expect(has(f, 'BCR-COOKIE-003')).toBe(true);
  });

  test('express-session with httpOnly: false fires BCR-COOKIE-001', () => {
    const f = scan('session-config.ts', `
      import session from 'express-session';
      export const mw = session({
        secret: process.env.SECRET as string,
        cookie: { httpOnly: false, secure: true },
      });
    `);
    expect(has(f, 'BCR-COOKIE-001')).toBe(true);
  });

  test('express-session with secure default-true library does NOT flag missing httpOnly', () => {
    const f = scan('session-default.ts', `
      import session from 'express-session';
      export const mw = session({
        secret: process.env.SECRET as string,
        cookie: { secure: true, sameSite: 'lax' },
      });
    `);
    // httpOnly defaults to true in express-session, so a missing httpOnly is not a finding.
    expect(has(f, 'BCR-COOKIE-001')).toBe(false);
  });
});
