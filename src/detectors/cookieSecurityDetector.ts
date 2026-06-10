import * as ts from 'typescript';
import { Confidence, DetectorResult, Finding } from '../types';
import { ASTParser } from '../parser/astParser';
import { ASTVisitor } from '../parser/astVisitor';

/**
 * Cookie security-flag detector.
 *
 * Session and authentication cookies that omit the hardening flags are a direct path to
 * session hijacking (no httpOnly → readable by injected JS), credential theft over the
 * network (no secure → sent in cleartext on the first HTTP hop), and CSRF (no sameSite).
 *
 *   - BCR-COOKIE-001: httpOnly disabled. Either an explicit `httpOnly: false`, or a
 *     `res.cookie()` for a session/auth-named cookie left at Express's insecure default
 *     (res.cookie does NOT set httpOnly unless you ask).
 *   - BCR-COOKIE-002: secure flag absent / false on a session or auth cookie (heuristic).
 *   - BCR-COOKIE-003: sameSite absent, or `sameSite: 'none'`, on a session/auth cookie
 *     (heuristic — CSRF exposure).
 *
 * The detector understands three cookie-setting shapes:
 *   - `res.cookie(name, value, options)`            (Express)
 *   - `session({ cookie: { ... } })`                (express-session)
 *   - `cookieSession({ ... })`                      (cookie-session)
 *
 * For `express-session` / `cookie-session` the library default for httpOnly is already
 * `true`, so a MISSING httpOnly is not flagged there — only an explicit `httpOnly: false`.
 * For `res.cookie` the default is insecure, so a missing httpOnly on a sensitive cookie is.
 */
export class CookieSecurityDetector {
  private findings: Finding[] = [];

  private static readonly SENSITIVE_COOKIE =
    /(^|[._-])(sess|session|sid|sso|auth|token|jwt|refresh|access|login|remember|csrf|xsrf)/i;

  constructor(
    private filePath: string,
    private sourceFile: ts.SourceFile,
    private parser: ASTParser
  ) {}

  detect(): DetectorResult {
    this.findings = [];

    ASTVisitor.findCallExpressions(this.sourceFile).forEach((call) => {
      this.checkResCookie(call);
      this.checkSessionConfig(call);
    });

    return { findings: this.findings };
  }

  // ── res.cookie(name, value, options) ───────────────────────────────────────
  private checkResCookie(call: ts.CallExpression): void {
    const callee = call.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    if (callee.name.text !== 'cookie') return;
    // Receiver should look like an HTTP response object (res / response / reply / ctx.res).
    const receiver = callee.expression.getText(this.sourceFile);
    if (!/\b(res|response|reply)\b/i.test(receiver)) return;

    const nameArg = call.arguments[0];
    const cookieName = nameArg && ts.isStringLiteralLike(nameArg) ? nameArg.text : '';
    // Only a *known* session/auth-shaped name is "sensitive". A dynamic/non-literal name
    // (`res.cookie(nameVar, …)`) is treated as NOT sensitive — otherwise every dynamically
    // named cookie would be flagged for a missing flag, a large false-positive class.
    const sensitive = cookieName !== '' && CookieSecurityDetector.SENSITIVE_COOKIE.test(cookieName);

    const opts = call.arguments[2];
    const options = opts && ts.isObjectLiteralExpression(opts) ? opts : undefined;

    const httpOnly = this.flagState(options, 'httpOnly');
    const secure = this.flagState(options, 'secure');
    const sameSite = this.sameSiteState(options);

    // httpOnly: explicit false is always a problem; missing is a problem for res.cookie
    // (insecure default) but only worth flagging on a sensitive cookie to stay high-signal.
    if (httpOnly === 'false') {
      this.emitHttpOnly(call, cookieName, 'FIRM', false);
    } else if (httpOnly === 'absent' && sensitive) {
      this.emitHttpOnly(call, cookieName, 'TENTATIVE', true);
    }

    if (sensitive && (secure === 'false' || secure === 'absent')) {
      this.emitSecure(call, cookieName, secure === 'false' ? 'FIRM' : 'TENTATIVE', secure === 'absent');
    }

    if (sensitive && (sameSite === 'none' || sameSite === 'absent')) {
      this.emitSameSite(call, cookieName, sameSite === 'none' ? 'FIRM' : 'TENTATIVE', sameSite === 'absent');
    }
  }

  // ── session({ cookie: {...} }) / cookieSession({...}) ──────────────────────
  private checkSessionConfig(call: ts.CallExpression): void {
    const callee = call.expression;
    const name = ts.isIdentifier(callee)
      ? callee.text
      : ts.isPropertyAccessExpression(callee)
        ? callee.name.text
        : '';
    const isSession = /^session$/i.test(name);
    const isCookieSession = /^cookieSession$/i.test(name);
    if (!isSession && !isCookieSession) return;

    const arg = call.arguments[0];
    if (!arg || !ts.isObjectLiteralExpression(arg)) return;

    // express-session nests the flags under `cookie`; cookie-session puts them at top level.
    let cookieObj: ts.ObjectLiteralExpression | undefined = isCookieSession ? arg : undefined;
    if (isSession) {
      for (const prop of arg.properties) {
        if (
          ts.isPropertyAssignment(prop) &&
          this.propName(prop.name) === 'cookie' &&
          ts.isObjectLiteralExpression(prop.initializer)
        ) {
          cookieObj = prop.initializer;
        }
      }
    }

    // Library default for httpOnly is true here, so only an EXPLICIT false is a finding.
    const httpOnly = this.flagState(cookieObj, 'httpOnly');
    if (httpOnly === 'false') {
      this.emitHttpOnly(call, name, 'FIRM', false);
    }

    const secure = this.flagState(cookieObj, 'secure');
    if (secure === 'false' || secure === 'absent') {
      this.emitSecure(call, name, secure === 'false' ? 'FIRM' : 'TENTATIVE', secure === 'absent');
    }

    const sameSite = this.sameSiteState(cookieObj);
    if (sameSite === 'none' || sameSite === 'absent') {
      this.emitSameSite(call, name, sameSite === 'none' ? 'FIRM' : 'TENTATIVE', sameSite === 'absent');
    }
  }

  // ── emit helpers ───────────────────────────────────────────────────────────
  private emitHttpOnly(call: ts.CallExpression, cookieName: string, confidence: Confidence, missing: boolean): void {
    const label = cookieName ? `\`${cookieName}\`` : 'the cookie';
    this.emit(call, {
      ruleId: 'BCR-COOKIE-001',
      severity: 'HIGH',
      confidence,
      title: 'Session/Auth Cookie Without httpOnly Flag',
      description: missing
        ? `${label} is set without \`httpOnly\`. res.cookie() does not enable httpOnly by default, so the cookie is readable from client-side JavaScript — a cross-site scripting flaw can then steal the session.`
        : `${label} is set with \`httpOnly: false\`, making it readable from client-side JavaScript. A cross-site scripting flaw can read the cookie and hijack the session.`,
      recommendation: 'Set `httpOnly: true` on session and authentication cookies so they are never exposed to JavaScript (document.cookie).',
    });
  }

  private emitSecure(call: ts.CallExpression, cookieName: string, confidence: Confidence, missing: boolean): void {
    const label = cookieName ? `\`${cookieName}\`` : 'the cookie';
    this.emit(call, {
      ruleId: 'BCR-COOKIE-002',
      severity: 'MEDIUM',
      confidence,
      title: 'Session/Auth Cookie Without Secure Flag',
      description: missing
        ? `${label} is set without the \`secure\` flag, so the browser will send it over plaintext HTTP. A network attacker on the first non-HTTPS hop can capture the session.`
        : `${label} is set with \`secure: false\`, so the browser will transmit it over plaintext HTTP where it can be intercepted.`,
      recommendation: 'Set `secure: true` (in production) so session/auth cookies are only ever sent over HTTPS.',
    });
  }

  private emitSameSite(call: ts.CallExpression, cookieName: string, confidence: Confidence, missing: boolean): void {
    const label = cookieName ? `\`${cookieName}\`` : 'the cookie';
    this.emit(call, {
      ruleId: 'BCR-COOKIE-003',
      severity: 'LOW',
      confidence,
      title: 'Session/Auth Cookie Without SameSite Attribute',
      description: missing
        ? `${label} is set without a \`sameSite\` attribute, leaving it attached to cross-site requests and exposed to cross-site request forgery.`
        : `${label} is set with \`sameSite: 'none'\`, which attaches it to all cross-site requests and removes the built-in CSRF mitigation.`,
      recommendation: "Set `sameSite: 'lax'` (or `'strict'`) on session/auth cookies, and pair `'none'` with `secure: true` only when cross-site use is genuinely required.",
    });
  }

  /** Reads a boolean flag: 'true' | 'false' | 'absent' (also 'absent' when no options object). */
  private flagState(obj: ts.ObjectLiteralExpression | undefined, flag: string): 'true' | 'false' | 'absent' {
    if (!obj) return 'absent';
    for (const prop of obj.properties) {
      if (!ts.isPropertyAssignment(prop)) continue;
      if (this.propName(prop.name) !== flag) continue;
      if (prop.initializer.kind === ts.SyntaxKind.TrueKeyword) return 'true';
      if (prop.initializer.kind === ts.SyntaxKind.FalseKeyword) return 'false';
      // A non-literal (e.g. `secure: isProd`) — treat as configured; do not flag.
      return 'true';
    }
    return 'absent';
  }

  /** Reads sameSite: 'set' (lax/strict/true) | 'none' | 'absent'. */
  private sameSiteState(obj: ts.ObjectLiteralExpression | undefined): 'set' | 'none' | 'absent' {
    if (!obj) return 'absent';
    for (const prop of obj.properties) {
      if (!ts.isPropertyAssignment(prop)) continue;
      if (this.propName(prop.name) !== 'sameSite') continue;
      const init = prop.initializer;
      if (ts.isStringLiteralLike(init)) return init.text.toLowerCase() === 'none' ? 'none' : 'set';
      // `sameSite: false` means "do not emit a SameSite attribute" — i.e. absent, not 'none'.
      if (init.kind === ts.SyntaxKind.FalseKeyword) return 'absent';
      return 'set';
    }
    return 'absent';
  }

  private propName(name: ts.PropertyName): string {
    if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
    return '';
  }

  private emit(
    call: ts.CallExpression,
    shape: {
      ruleId: string;
      severity: Finding['severity'];
      confidence: Confidence;
      title: string;
      description: string;
      recommendation: string;
    }
  ): void {
    const { line, column } = this.parser.getLineAndColumn(call.getStart());
    this.findings.push({
      ruleId: shape.ruleId,
      category: 'MISCONFIGURATION',
      severity: shape.severity,
      confidence: shape.confidence,
      title: shape.title,
      description: shape.description,
      file: this.filePath,
      line,
      column,
      code: call.getText().substring(0, 140),
      recommendation: shape.recommendation,
    });
  }
}
