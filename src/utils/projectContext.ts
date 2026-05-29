import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';
import { ASTVisitor } from '../parser/astVisitor';
import { buildImportAliasMap, buildReExportList, ImportAlias, ReExport } from './importAliases';
import { isUntrustedInputText } from './detectorLogic';

/**
 * Project-wide analysis context.
 *
 * Lightweight cross-file taint + dangerous-API tracking. Avoids the full
 * TypeScript Compiler API (per-project tsconfig discovery is fragile in monorepos)
 * by doing a two-pass scan:
 *
 *   Pass 1 — `addFile()` collects per-module export summaries:
 *     • Re-export descriptors (`export { exec } from 'child_process'`)
 *     • Function-export taint summaries (does the return value depend on a
 *       user-controlled source inside the function body?)
 *     • Re-exported dangerous APIs (transitively resolved)
 *
 *   Pass 2 — detectors consult `resolveImportedSymbol()` to follow any local
 *     import name across the re-export graph to its canonical (module, name)
 *     and any cached behavior summary.
 *
 * This catches the highest-frequency cross-file vulnerability shapes that the
 * single-file scanner misses today:
 *
 *   1. `A.ts: export { exec } from 'child_process'`
 *      `B.ts: import { exec } from './a'; exec(req.body.cmd)`
 *
 *   2. `A.ts: export function getId(req) { return req.params.id; }`
 *      `B.ts: import { getId } from './a'; db.query(\`… ${getId(req)}\`)`
 *
 *   3. Multi-hop re-export chains.
 *
 * Out of scope (intentional):
 *   - Inter-procedural taint THROUGH calls to non-exported helpers (covered by
 *     the in-file `TaintTracker`).
 *   - Class-method-level summaries (a single per-class summary is approximated
 *     by union over its methods — conservative but lossy).
 *   - Full type-driven aliasing (would need TypeChecker).
 */

export interface FunctionExportSummary {
  /** True when the function's return value derives from a user-controlled source. */
  returnsTaintedFromRequest: boolean;
  /** True when the function passes a parameter directly into a dangerous sink. */
  passesParamToSink: boolean;
  /**
   * If the function is itself a re-export wrapper (delegates to an imported function),
   * the canonical target. Used to follow multi-hop chains.
   */
  delegatesTo?: { module: string; name: string };
}

export interface ModuleExports {
  /** Canonical file path. */
  filePath: string;
  /** Re-exports declared in this module. */
  reExports: ReExport[];
  /** Per-exported-name behavioral summary. */
  functionSummaries: Map<string, FunctionExportSummary>;
}

export interface ResolvedSymbol {
  /** The canonical module — either a node-builtin/npm-module name or a file path. */
  module: string;
  /** The canonical exported name. */
  exportedName: string;
  /** The full chain of intermediate modules walked (for debugging / reporting). */
  hops: Array<{ module: string; name: string }>;
  /** Behavior summary if the symbol resolves to a known function. */
  summary?: FunctionExportSummary;
}

/**
 * Known dangerous APIs by canonical (module, name). When an aliased import resolves
 * to one of these, the call site is treated as a sink — independent of how many
 * re-export hops were between the import and the original.
 */
const DANGEROUS_BUILTINS: Array<{ module: string; name: string; rule: 'BCR-VAL-002' | 'BCR-VAL-003' }> = [
  { module: 'child_process', name: 'exec', rule: 'BCR-VAL-002' },
  { module: 'child_process', name: 'execSync', rule: 'BCR-VAL-002' },
  { module: 'child_process', name: 'spawn', rule: 'BCR-VAL-002' },
  { module: 'child_process', name: 'spawnSync', rule: 'BCR-VAL-002' },
  { module: 'child_process', name: 'execFile', rule: 'BCR-VAL-002' },
  { module: 'child_process', name: 'execFileSync', rule: 'BCR-VAL-002' },
  { module: 'child_process', name: 'fork', rule: 'BCR-VAL-002' },
  { module: 'vm', name: 'runInThisContext', rule: 'BCR-VAL-003' },
  { module: 'vm', name: 'runInNewContext', rule: 'BCR-VAL-003' },
  { module: 'vm', name: 'runInContext', rule: 'BCR-VAL-003' },
];

function isDangerousBuiltin(module: string, name: string): boolean {
  return DANGEROUS_BUILTINS.some((d) => d.module === module && d.name === name);
}

export class ProjectContext {
  /** filePath → its export summary. */
  private modules = new Map<string, ModuleExports>();
  /** Aliases per file — populated as files are added. */
  private aliasesByFile = new Map<string, Map<string, ImportAlias>>();

  /** Whether the context has any files registered. */
  get isEmpty(): boolean {
    return this.modules.size === 0;
  }

  /** Number of distinct modules indexed. */
  get size(): number {
    return this.modules.size;
  }

  /**
   * Register a parsed file. Builds the import-alias map, re-export descriptors,
   * and per-exported-name summaries.
   */
  addFile(filePath: string, sourceFile: ts.SourceFile): void {
    const canonical = path.resolve(filePath);
    const aliases = buildImportAliasMap(sourceFile);
    this.aliasesByFile.set(canonical, aliases);

    const reExports = buildReExportList(sourceFile);
    const functionSummaries = new Map<string, FunctionExportSummary>();
    this.collectFunctionExports(sourceFile, aliases, functionSummaries);

    this.modules.set(canonical, {
      filePath: canonical,
      reExports,
      functionSummaries,
    });
  }

  /**
   * Given a file and a local import alias, follow re-export chains to the canonical
   * (module, name) and return the behavior summary if available.
   *
   * Returns null when the alias cannot be resolved (e.g. third-party module not in
   * this project) — callers should fall back to the in-file alias resolver.
   */
  resolveImportedSymbol(fromFilePath: string, alias: ImportAlias): ResolvedSymbol | null {
    const hops: Array<{ module: string; name: string }> = [];
    let currentModule = alias.module;
    let currentName = alias.exportedName;
    let currentFromFile = path.resolve(fromFilePath);

    // Limit hop count to prevent infinite loops on circular re-exports.
    const HOP_LIMIT = 16;
    for (let i = 0; i < HOP_LIMIT; i++) {
      hops.push({ module: currentModule, name: currentName });

      // 1. Resolve `currentModule` to a project file path (relative imports only).
      const targetFile = this.resolveModuleToFile(currentFromFile, currentModule);
      if (!targetFile) {
        // External / node-builtin module — terminal.
        return { module: currentModule, exportedName: currentName, hops };
      }

      const targetSummary = this.modules.get(targetFile);
      if (!targetSummary) {
        return { module: currentModule, exportedName: currentName, hops };
      }

      // 2. Check if the target file re-exports the name through another module.
      // Prefer a specific (named) re-export over a wildcard so that
      // `export { foo } from './b'; export * from './a';` correctly resolves
      // `foo` against `'./b'`, not `'./a'`.
      const reExport =
        targetSummary.reExports.find((r) => r.exportedName === currentName) ??
        targetSummary.reExports.find((r) => r.exportedName === '*');
      if (reExport) {
        const nextName = reExport.exportedName === '*' ? currentName : reExport.upstreamName;
        currentModule = reExport.fromModule;
        currentName = nextName;
        currentFromFile = targetFile;
        continue;
      }

      // 3. Otherwise, look up the function summary in the target file.
      const summary = targetSummary.functionSummaries.get(currentName);
      return {
        module: currentModule,
        exportedName: currentName,
        hops,
        summary,
      };
    }
    return { module: currentModule, exportedName: currentName, hops };
  }

  /**
   * True when the call expression's callee resolves (transitively through any chain
   * of project re-exports) to a known dangerous Node API.
   */
  callResolvesToDangerousBuiltin(
    fromFilePath: string,
    call: ts.CallExpression
  ): { module: string; name: string } | null {
    const aliases = this.aliasesByFile.get(path.resolve(fromFilePath));
    if (!aliases) return null;

    const expr = call.expression;
    let localName: string | undefined;
    let alias: ImportAlias | undefined;

    if (ts.isIdentifier(expr)) {
      localName = expr.text;
      alias = aliases.get(localName);
    } else if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
      const receiver = expr.expression.text;
      const receiverAlias = aliases.get(receiver);
      if (!receiverAlias) return null;
      alias = { module: receiverAlias.module, exportedName: expr.name.text };
    }

    if (!alias) return null;
    const resolved = this.resolveImportedSymbol(fromFilePath, alias);
    if (!resolved) return null;
    if (isDangerousBuiltin(resolved.module, resolved.exportedName)) {
      return { module: resolved.module, name: resolved.exportedName };
    }
    return null;
  }

  /**
   * True when the call expression invokes an imported function whose summary says
   * its return value derives from a user-controlled source (transitive re-exports
   * followed).
   */
  callReturnsTaintedFromRequest(fromFilePath: string, call: ts.CallExpression): boolean {
    const aliases = this.aliasesByFile.get(path.resolve(fromFilePath));
    if (!aliases) return false;

    const expr = call.expression;
    if (!ts.isIdentifier(expr)) return false;
    const alias = aliases.get(expr.text);
    if (!alias) return false;

    const resolved = this.resolveImportedSymbol(fromFilePath, alias);
    return Boolean(resolved?.summary?.returnsTaintedFromRequest);
  }

  /** Resolves `import './a'` against the importing file's directory. */
  private resolveModuleToFile(fromFile: string, moduleSpecifier: string): string | null {
    // Relative imports only — bare specifiers are external.
    if (!moduleSpecifier.startsWith('.') && !moduleSpecifier.startsWith('/')) {
      return null;
    }
    const fromDir = path.dirname(fromFile);
    const base = path.resolve(fromDir, moduleSpecifier);
    const candidates = [
      base,
      `${base}.ts`,
      `${base}.tsx`,
      `${base}.js`,
      path.join(base, 'index.ts'),
      path.join(base, 'index.tsx'),
      path.join(base, 'index.js'),
    ];
    for (const candidate of candidates) {
      const resolved = path.resolve(candidate);
      if (this.modules.has(resolved)) return resolved;
      if (fs.existsSync(resolved)) return resolved;
    }
    return null;
  }

  /**
   * Walk every exported function declaration / arrow / method in the file and
   * compute a lightweight per-name summary.
   */
  private collectFunctionExports(
    sourceFile: ts.SourceFile,
    aliases: Map<string, ImportAlias>,
    summaries: Map<string, FunctionExportSummary>
  ): void {
    for (const statement of sourceFile.statements) {
      // `export function foo(req) { … }`
      if (ts.isFunctionDeclaration(statement) && this.isExported(statement)) {
        const name = statement.name?.text;
        const summary = this.summarizeFunctionBody(statement);
        if (name) summaries.set(name, summary);
        // `export default function (req) { … }` — register under 'default'.
        const mods = ts.canHaveModifiers(statement) ? (ts.getModifiers(statement) ?? []) : [];
        if (mods.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) {
          summaries.set('default', summary);
        }
        continue;
      }
      // `export default …` — bare expression form.
      if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
        const expr = statement.expression;
        if (ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)) {
          summaries.set('default', this.summarizeFunctionBody(expr));
        }
        continue;
      }
      // `export const foo = (req) => …` / `export const foo = function (req) { … }`
      if (ts.isVariableStatement(statement) && this.isExported(statement)) {
        for (const decl of statement.declarationList.declarations) {
          if (!ts.isIdentifier(decl.name)) continue;
          const name = decl.name.text;
          const initializer = decl.initializer;
          if (!initializer) continue;
          if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
            summaries.set(name, this.summarizeFunctionBody(initializer));
          }
        }
        continue;
      }
      // `export class Foo { method(req) { … } }` — approximate union over methods.
      if (ts.isClassDeclaration(statement) && this.isExported(statement) && statement.name) {
        for (const member of statement.members) {
          if (ts.isMethodDeclaration(member) && member.name && ts.isIdentifier(member.name)) {
            const methodName = member.name.text;
            const summary = this.summarizeFunctionBody(member);
            // Class methods are exported as `ClassName.methodName` for the resolver.
            summaries.set(`${statement.name.text}.${methodName}`, summary);
          }
        }
      }
    }
    void aliases; // reserved for future delegation detection.
  }

  private isExported(node: ts.HasModifiers): boolean {
    return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some(
      (m) => m.kind === ts.SyntaxKind.ExportKeyword
    );
  }

  private summarizeFunctionBody(
    node: ts.FunctionLikeDeclaration
  ): FunctionExportSummary {
    let returnsTaintedFromRequest = false;
    let passesParamToSink = false;

    if (node.body) {
      // Walk return statements ONLY for this function's body, not nested function bodies.
      // Previously a `return req.body.x` inside an inner `.map(x => req.body.x)` would
      // falsely mark the OUTER function as returning tainted data.
      const directReturns: ts.ReturnStatement[] = [];
      const collectReturns = (n: ts.Node): void => {
        if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) ||
            ts.isArrowFunction(n) || ts.isMethodDeclaration(n)) {
          // Don't descend into nested function bodies — their returns belong to that
          // function, not this one.
          return;
        }
        if (ts.isReturnStatement(n)) directReturns.push(n);
        n.forEachChild(collectReturns);
      };
      node.body.forEachChild(collectReturns);
      for (const ret of directReturns) {
        const expr = ret.expression;
        if (!expr) continue;
        const text = expr.getText(node.getSourceFile());
        if (isUntrustedInputText(text)) {
          returnsTaintedFromRequest = true;
          break;
        }
      }

      // Walk dangerous-sink call expressions where any param of the function flows in.
      const paramNames = new Set<string>();
      for (const param of node.parameters) {
        if (ts.isIdentifier(param.name)) paramNames.add(param.name.text);
      }
      if (paramNames.size > 0) {
        ASTVisitor.findNodes(node.body, (n) => ts.isCallExpression(n)).forEach((callNode) => {
          const call = callNode as ts.CallExpression;
          const calleeText = call.expression.getText(node.getSourceFile());
          // Strict sink set — match the validation detector's anchored names.
          if (!/\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|eval)\b|JSON\.parse|\.query\(|\.raw\(/i.test(calleeText)) return;
          for (const arg of call.arguments) {
            const argText = arg.getText(node.getSourceFile());
            for (const param of paramNames) {
              if (new RegExp(`\\b${param}\\b`).test(argText)) {
                passesParamToSink = true;
              }
            }
          }
        });
      }
    }

    return { returnsTaintedFromRequest, passesParamToSink };
  }
}
