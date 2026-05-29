import * as ts from 'typescript';

/**
 * Lightweight import-alias resolver.
 *
 * The TypeScript compiler-API integration would give us symbol resolution out of the
 * box, but it requires per-project tsconfig discovery (fragile in monorepos) and is
 * expensive on large codebases. For the dangerous-API recognition use case we don't
 * need full symbol resolution — we only need to know "in THIS file, what does the name
 * `runShell` refer to?" That's a 30-line AST scan.
 *
 * Returns a map from local-binding-name → { module, exportedName }. For example, given
 *
 *   import { exec as runShell } from 'child_process';
 *   const { parse: parseJson } = require('JSON');
 *
 * the map contains:
 *   runShell  → { module: 'child_process', exportedName: 'exec' }
 *   parseJson → { module: 'JSON', exportedName: 'parse' }
 *
 * The dangerous-sink detectors can then ask "is this call resolving to a known
 * dangerous function regardless of local name?" and stop missing renamed imports.
 */

export interface ImportAlias {
  /** The module specifier the alias came from. */
  module: string;
  /** The name exported by the module (the right-hand side of `as`, or the bare name). */
  exportedName: string;
}

export function buildImportAliasMap(sourceFile: ts.SourceFile): Map<string, ImportAlias> {
  const aliases = new Map<string, ImportAlias>();

  for (const statement of sourceFile.statements) {
    // ES module imports: `import { exec as runShell } from 'child_process';`
    if (ts.isImportDeclaration(statement) && statement.importClause) {
      const moduleSpecifier = statement.moduleSpecifier;
      if (!ts.isStringLiteral(moduleSpecifier)) continue;
      const moduleName = moduleSpecifier.text;
      const clause = statement.importClause;

      // Default import: `import fs from 'fs';` → fs aliases to module's default export.
      if (clause.name) {
        aliases.set(clause.name.text, { module: moduleName, exportedName: 'default' });
      }

      const named = clause.namedBindings;
      if (named) {
        if (ts.isNamespaceImport(named)) {
          // `import * as fs from 'fs';` — fs is the whole namespace.
          aliases.set(named.name.text, { module: moduleName, exportedName: '*' });
        } else if (ts.isNamedImports(named)) {
          for (const element of named.elements) {
            const localName = element.name.text;
            const exportedName = element.propertyName ? element.propertyName.text : localName;
            aliases.set(localName, { module: moduleName, exportedName });
          }
        }
      }
    }

    // CJS-style destructuring: `const { exec: runShell } = require('child_process');`
    if (ts.isVariableStatement(statement)) {
      for (const decl of statement.declarationList.declarations) {
        const initializer = decl.initializer;
        if (!initializer || !ts.isCallExpression(initializer)) continue;
        if (!ts.isIdentifier(initializer.expression) || initializer.expression.text !== 'require') continue;
        const firstArg = initializer.arguments[0];
        if (!firstArg || !ts.isStringLiteral(firstArg)) continue;
        const moduleName = firstArg.text;

        if (ts.isIdentifier(decl.name)) {
          aliases.set(decl.name.text, { module: moduleName, exportedName: '*' });
        } else if (ts.isObjectBindingPattern(decl.name)) {
          for (const element of decl.name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            const localName = element.name.text;
            const exportedName = element.propertyName && ts.isIdentifier(element.propertyName)
              ? element.propertyName.text
              : localName;
            aliases.set(localName, { module: moduleName, exportedName });
          }
        }
      }
    }
  }

  return aliases;
}

/**
 * Re-export descriptor: `export { exec } from 'child_process'` or `export * from './a'`.
 * Used by the project-context cross-file resolver to follow re-export chains so that
 * an aliased re-export of a dangerous import still resolves to the canonical name.
 */
export interface ReExport {
  /** Local exported name (what the consuming module imports). */
  exportedName: string;
  /** The upstream module specifier. */
  fromModule: string;
  /** The name in the upstream module (`'*'` for re-export-all). */
  upstreamName: string;
}

/**
 * Walks `ExportDeclaration` nodes and returns their re-export descriptors. This
 * complements `buildImportAliasMap` for the export side; together they let the
 * project context follow taint or dangerous-API references across re-export chains.
 *
 * Handles:
 *   - `export { exec } from 'child_process';`
 *   - `export { exec as runShell } from 'child_process';`
 *   - `export * from './shared';`
 *   - `export * as utils from './utils';`  (namespace re-export)
 */
export function buildReExportList(sourceFile: ts.SourceFile): ReExport[] {
  const out: ReExport[] = [];
  for (const statement of sourceFile.statements) {
    if (!ts.isExportDeclaration(statement)) continue;
    const moduleSpecifier = statement.moduleSpecifier;
    if (!moduleSpecifier || !ts.isStringLiteral(moduleSpecifier)) continue;
    const fromModule = moduleSpecifier.text;
    const clause = statement.exportClause;
    if (!clause) {
      // `export * from './shared'` — re-export-all.
      out.push({ exportedName: '*', fromModule, upstreamName: '*' });
      continue;
    }
    if (ts.isNamespaceExport(clause)) {
      // `export * as utils from './utils'`
      out.push({ exportedName: clause.name.text, fromModule, upstreamName: '*' });
      continue;
    }
    if (ts.isNamedExports(clause)) {
      for (const element of clause.elements) {
        const exportedName = element.name.text;
        const upstreamName = element.propertyName ? element.propertyName.text : exportedName;
        out.push({ exportedName, fromModule, upstreamName });
      }
    }
  }
  return out;
}

/**
 * Given a call expression and an alias map, return the canonical exported name of the
 * callee — useful for "is this really `exec`, or `path.join`, regardless of local name?"
 *
 * Returns null when the call's callee cannot be resolved to an aliased import.
 */
export function resolveCalleeToExportedName(
  call: ts.CallExpression,
  aliases: Map<string, ImportAlias>
): { module: string; exportedName: string } | null {
  const expr = call.expression;

  // `runShell(...)` — bare identifier.
  if (ts.isIdentifier(expr)) {
    return aliases.get(expr.text) ?? null;
  }

  // `fs.readFileSync(...)` — PropertyAccess; the receiver is what was imported.
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
    const receiver = expr.expression.text;
    const receiverAlias = aliases.get(receiver);
    if (!receiverAlias) return null;
    if (receiverAlias.exportedName === '*' || receiverAlias.exportedName === 'default') {
      return { module: receiverAlias.module, exportedName: expr.name.text };
    }
    // Renamed default? Rare. Fall through with the property name.
    return { module: receiverAlias.module, exportedName: expr.name.text };
  }

  return null;
}
