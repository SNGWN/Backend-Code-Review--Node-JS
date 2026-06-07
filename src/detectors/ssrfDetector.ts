import * as ts from 'typescript';
import { DetectorResult, Finding } from '../types';
import { ASTParser } from '../parser/astParser';
import { ASTVisitor } from '../parser/astVisitor';
import { TaintTracker } from '../utils/taint';
import { buildImportAliasMap, ImportAlias, resolveCalleeToExportedName } from '../utils/importAliases';
import { ProjectContext } from '../utils/projectContext';

/**
 * Containment indicators for path-traversal heuristics. Returns true when the enclosing
 * function clearly enforces a base-directory check: `path.resolve(BASE_DIR, ...)` paired
 * with a `.startsWith(BASE_DIR)` containment check, or a known containment helper.
 */
function hasPathContainmentCheck(text: string): boolean {
  // Helpers that signal containment regardless of receiver.
  if (/\b(iswithin|containspath|sanitizepath|pathisinside|path-is-inside|safePath|validatePath)\b/i.test(text)) {
    return true;
  }
  // `path.resolve(BASE, name)` + `.startsWith(BASE)` — the canonical containment idiom.
  // The variable name is irrelevant; we just need to see a resolve + a startsWith in the
  // same function.
  if (/\bpath\.resolve\s*\(/i.test(text) && /\.startsWith\s*\(/i.test(text)) {
    return true;
  }
  // `path.resolve` with a base-directory constant pattern.
  if (/\bpath\.resolve\s*\([^,)]*\b(base|root|allowed|safe|trusted)[_-]?(dir|path|root)\b/i.test(text)) {
    return true;
  }
  return false;
}

/**
 * SSRF + Open Redirect + Path Traversal detector.
 *
 * Three closely-related dataflow vulnerabilities the audit identified as missing:
 *   - SSRF: outbound HTTP request with user-controlled URL
 *   - Open Redirect: res.redirect/Location header with user-controlled URL
 *   - Path Traversal: filesystem sink with user-controlled path
 *
 * All three are intra-procedural taint checks: source = request data, sink = a
 * specific call. The TaintTracker handles validator-aware detainting (zod, ajv, etc.)
 * and the strict argument-shape checks below keep FP low.
 */
export class SsrfDetector {
  private findings: Finding[] = [];
  private taintTracker: TaintTracker | null = null;
  private aliasMap: Map<string, ImportAlias> = new Map();

  constructor(
    private filePath: string,
    private sourceFile: ts.SourceFile,
    private parser: ASTParser,
    private projectContext: ProjectContext | null = null
  ) {}

  detect(): DetectorResult {
    this.findings = [];
    this.taintTracker = new TaintTracker(this.sourceFile);
    this.aliasMap = buildImportAliasMap(this.sourceFile);

    ASTVisitor.findCallExpressions(this.sourceFile).forEach((call) => {
      this.checkOutboundHttp(call);
      this.checkOpenRedirect(call);
      this.checkPathTraversal(call);
    });

    return { findings: this.findings };
  }

  private checkOutboundHttp(call: ts.CallExpression): void {
    const sinkName = this.getCallSinkName(call);
    if (!sinkName) return;

    // Outbound HTTP sinks. Bare-callable clients (`fetch`/`got`/`ky`/`needle`/`axios`/…) and
    // method calls on an http-client-shaped receiver. The receiver set includes common
    // axios.create()/got.extend() instance names (client/httpClient/api/agent/instance/svc) so
    // `const client = axios.create(); client.get(userUrl)` is covered. Anchored, not substring.
    const outboundShape = /^(fetch|axios|got|ky|needle|request|superagent|undici|phin)$|^(axios|got|ky|needle|http|https|client|httpClient|httpclient|api|apiClient|agent|instance|svc|service|gateway|upstream)\.(get|post|put|delete|patch|head|request|stream)$/i;
    if (!outboundShape.test(sinkName)) return;

    const urlArg = call.arguments[0];
    if (!urlArg) return;
    if (!this.argReferencesUser(urlArg)) return;
    if (this.isInValidationContext(call)) return;

    const { line, column } = this.parser.getLineAndColumn(call.getStart());
    this.findings.push({
      ruleId: 'BCR-SSRF-001',
      category: 'SSRF',
      severity: 'CRITICAL',
      title: 'SSRF: Outbound Request Built From User Input',
      description: `Outbound HTTP call \`${sinkName}\` constructs its URL from user-controlled data without a visible allowlist.`,
      file: this.filePath,
      line,
      column,
      code: call.getText().substring(0, 140),
      recommendation:
        'Constrain outbound URLs through a server-side allowlist of hosts and schemes. Reject non-HTTPS and non-public destinations.',
    });
  }

  private checkOpenRedirect(call: ts.CallExpression): void {
    // res.redirect(url) — Express idiom. Also res.set('Location', url) and res.location(url).
    const expr = call.expression;
    if (!ts.isPropertyAccessExpression(expr)) return;
    const receiver = ts.isIdentifier(expr.expression) ? expr.expression.text : '';
    const method = expr.name.text;

    let urlArg: ts.Expression | undefined;
    if ((receiver === 'res' || receiver === 'response' || receiver === 'reply') && method === 'redirect') {
      // res.redirect(status?, url) — last arg is the URL
      urlArg = call.arguments[call.arguments.length - 1];
    } else if ((receiver === 'res' || receiver === 'response') && method === 'location') {
      urlArg = call.arguments[0];
    } else if ((receiver === 'res' || receiver === 'response') && method === 'set' && call.arguments.length === 2) {
      const first = call.arguments[0];
      if (ts.isStringLiteral(first) && first.text.toLowerCase() === 'location') {
        urlArg = call.arguments[1];
      }
    } else {
      return;
    }

    if (!urlArg) return;
    if (!this.argReferencesUser(urlArg)) return;
    if (this.isInValidationContext(call)) return;
    // Suppress when the URL is clearly relative-only (string literal prefix '/').
    if (this.isClearlyRelativePath(urlArg)) return;

    const { line, column } = this.parser.getLineAndColumn(call.getStart());
    this.findings.push({
      ruleId: 'BCR-REDIRECT-001',
      category: 'OPEN_REDIRECT',
      severity: 'HIGH',
      title: 'Open Redirect: res.redirect() Receives User Input',
      description: 'HTTP redirect target is taken from request data without validation.',
      file: this.filePath,
      line,
      column,
      code: call.getText().substring(0, 140),
      recommendation:
        'Validate the redirect URL against a server-side allowlist, or only allow relative paths starting with a single "/".',
    });
  }

  private checkPathTraversal(call: ts.CallExpression): void {
    const sinkName = this.getCallSinkName(call);
    if (!sinkName) return;

    const fsShape = /^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|stat|statSync|lstat|lstatSync|sendFile|download)$|\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|sendFile|download)$/;
    if (!fsShape.test(sinkName)) return;

    const pathArg = call.arguments[0];
    if (!pathArg) return;
    if (!this.argReferencesUser(pathArg)) return;
    if (this.isInValidationContext(call)) return;
    // Resolve / sanitize / containment indicators reduce FP.
    const enclosingText = this.getEnclosingFunctionText(call);
    if (hasPathContainmentCheck(enclosingText)) {
      return;
    }

    const { line, column } = this.parser.getLineAndColumn(call.getStart());
    this.findings.push({
      ruleId: 'BCR-PT-001',
      category: 'PATH_TRAVERSAL',
      severity: 'CRITICAL',
      title: 'Path Traversal: File-System Sink Reads User-Controlled Path',
      description: `Filesystem sink \`${sinkName}\` receives a path derived from user input without canonicalization or directory allowlist.`,
      file: this.filePath,
      line,
      column,
      code: call.getText().substring(0, 140),
      recommendation:
        'Resolve against a fixed base directory and reject any result outside it. Reject `..` segments and absolute paths.',
    });
  }

  private argReferencesUser(node: ts.Node): boolean {
    if (!this.taintTracker) return false;
    return this.taintTracker.isTainted(node);
  }

  private isInValidationContext(node: ts.Node): boolean {
    // Re-use the project's enclosing-scope validator detection. Critical fix: anchor
    // every validator name with \b so `joi` doesn't match inside `path.join`,
    // `yup` doesn't match inside `cleanup`, etc.
    const enclosing = this.getEnclosingFunctionText(node);
    return (
      /\b(joi|yup|zod|valibot|ajv|express[-_]?validator|safe[-_]?parse|allowlist|whitelist|sanitize)\b/i.test(enclosing) ||
      /\b(isUrl|isURL|validUrl)\s*\(/.test(enclosing) ||
      /\bnew\s+URL\s*\(/.test(enclosing) ||
      // Set-style allowlist .has(...) checks — common idiom for redirect/host validation.
      /\b(ALLOWED|WHITELIST|VALID|PERMITTED)_[A-Z0-9_]+\.has\s*\(/.test(enclosing)
    );
  }

  private isClearlyRelativePath(node: ts.Expression): boolean {
    if (ts.isStringLiteral(node)) {
      return node.text.startsWith('/') && !node.text.startsWith('//');
    }
    if (ts.isTemplateExpression(node)) {
      // Template starting with a literal '/'.
      const head = node.head.text;
      return head.startsWith('/') && !head.startsWith('//');
    }
    return false;
  }

  private getCallSinkName(call: ts.CallExpression): string {
    // Cross-file: if a project re-export chain resolves to a known dangerous Node API,
    // use the canonical (module, name) so the existing fsShape / outboundShape regex
    // catches it the same as a direct import.
    if (this.projectContext) {
      const xfile = this.projectContext.callResolvesToDangerousBuiltin(this.filePath, call);
      if (xfile) return `${xfile.module}.${xfile.name}`;
    }
    // Try the import-alias resolver first — if the local callee resolves to a known
    // exported name from a module, use the exported name. This catches renamed imports
    // (`import { readFileSync as slurp } from 'fs'; slurp(name)`).
    const resolved = resolveCalleeToExportedName(call, this.aliasMap);
    if (resolved) {
      // Emit a stable shape: `<module>.<exportedName>` or bare exported name for
      // matching against the fsShape / outboundShape regexes.
      return `${resolved.module}.${resolved.exportedName}`;
    }
    if (ts.isIdentifier(call.expression)) return call.expression.text;
    if (ts.isPropertyAccessExpression(call.expression)) {
      const receiver = ts.isIdentifier(call.expression.expression)
        ? call.expression.expression.text
        : '';
      return receiver ? `${receiver}.${call.expression.name.text}` : `.${call.expression.name.text}`;
    }
    return '';
  }

  /**
   * Exposed for the validation detector — it shares the same containment heuristic.
   */
  static enclosingHasPathContainmentCheck(text: string): boolean {
    return hasPathContainmentCheck(text);
  }

  private getEnclosingFunctionText(node: ts.Node): string {
    let current: ts.Node | undefined = node;
    while (current) {
      if (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current)
      ) {
        return current.getText(this.sourceFile);
      }
      current = current.parent;
    }
    return node.getText(this.sourceFile);
  }
}
