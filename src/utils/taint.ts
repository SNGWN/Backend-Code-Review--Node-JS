import * as ts from 'typescript';
import { ASTVisitor } from '../parser/astVisitor';
import { isUntrustedInputText } from './detectorLogic';

/**
 * Scope-aware taint tracking.
 *
 * The previous approach matched tainted variable names against arbitrary node text using
 * `new RegExp(\\b${variable}\\b)`. That collided on common variable names ("data",
 * "result", "input") whenever an unrelated local happened to share the name — producing
 * false positives at scale.
 *
 * This helper uses the AST instead:
 *   1. Build a map of tainted *symbols* (declaration nodes) by walking
 *      VariableDeclarations and BindingElements whose initializers reach a known
 *      untrusted source (req.body, req.query, etc.) or another tainted symbol.
 *   2. Resolve an Identifier usage to its declaration by walking enclosing scopes
 *      bottom-up — the FIRST matching declaration wins (proper shadowing).
 *   3. Mark a node "tainted" iff its identifier subtree references a declaration in
 *      the tainted set.
 *
 * This handles:
 *   - Shadowing: an inner `const data = ...` masks an outer tainted `data`.
 *   - Aliasing: `const safe = sanitize(req.body)` does NOT propagate taint because
 *     `safe`'s initializer's sub-identifiers are inspected.
 *   - Destructuring: `const { id } = req.params` marks `id` tainted (per-element).
 *
 * Limits (documented honest):
 *   - Single-file: cross-file flow is not tracked.
 *   - Function-call resolution: passing a tainted value through a helper that returns
 *     it is not propagated. The taint stops at the call boundary. Reduces FN coverage
 *     but eliminates a large class of FPs.
 *   - The set is computed in source-order so backward-flowing aliases are not seen.
 *     This is conservative on purpose.
 */
export class TaintTracker {
  private taintedDeclarations = new Set<ts.Node>();
  /** name → declaration nodes the name might resolve to (for fast prefiltering). */
  private declarationsByName = new Map<string, ts.Node[]>();
  /** validation/sanitization markers — declarations passed through these are detainted. */
  private validatedDeclarations = new Set<ts.Node>();

  constructor(private sourceFile: ts.SourceFile) {
    this.indexDeclarations();
    this.seedFromUntrustedSources();
    this.propagateThroughAliases();
  }

  /** Mark a declaration as having been validated (sanitization output). */
  markValidated(declaration: ts.Node): void {
    this.validatedDeclarations.add(declaration);
    this.taintedDeclarations.delete(declaration);

    // Destructuring: `const { host } = schema.parse(req.query)` — the seed phase added
    // the BindingElement of `host` to the tainted set; the validator pass marked the
    // outer VariableDeclaration as validated but the inner BindingElements stay
    // tainted unless we walk them here.
    if (ts.isVariableDeclaration(declaration) || ts.isBindingElement(declaration)) {
      const name = (declaration as ts.VariableDeclaration | ts.BindingElement).name;
      if (name && (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name))) {
        name.elements.forEach((element) => {
          if (ts.isBindingElement(element)) {
            this.validatedDeclarations.add(element);
            this.taintedDeclarations.delete(element);
          }
        });
      }
    }
  }

  /**
   * Returns true if `node` references a tainted identifier *transitively*.
   * Walks every identifier inside `node` and checks whether each resolves to a tainted
   * declaration in scope.
   */
  isTainted(node: ts.Node): boolean {
    const sourceText = node.getText(this.sourceFile);
    if (isUntrustedInputText(sourceText)) return true;

    let tainted = false;
    const visit = (current: ts.Node): void => {
      if (tainted) return;
      if (ts.isIdentifier(current)) {
        const declaration = this.resolveIdentifierToDeclaration(current);
        if (declaration && this.taintedDeclarations.has(declaration)) {
          tainted = true;
          return;
        }
      }
      ts.forEachChild(current, visit);
    };
    visit(node);
    return tainted;
  }

  private indexDeclarations(): void {
    ASTVisitor.visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node)) {
        this.registerBindingName(node.name, node);
      } else if (ts.isBindingElement(node)) {
        this.registerBindingName(node.name, node);
      } else if (ts.isParameter(node)) {
        this.registerBindingName(node.name, node);
      } else if (ts.isFunctionDeclaration(node) && node.name) {
        this.addDeclaration(node.name.text, node);
      }
    });
  }

  private registerBindingName(name: ts.BindingName, declaration: ts.Node): void {
    if (ts.isIdentifier(name)) {
      this.addDeclaration(name.text, declaration);
      return;
    }

    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      name.elements.forEach((element) => {
        if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
          this.addDeclaration(element.name.text, element);
        }
      });
    }
  }

  private addDeclaration(name: string, declaration: ts.Node): void {
    const existing = this.declarationsByName.get(name) ?? [];
    existing.push(declaration);
    this.declarationsByName.set(name, existing);
  }

  private seedFromUntrustedSources(): void {
    ASTVisitor.visit(this.sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        if (isUntrustedInputText(node.initializer.getText(this.sourceFile))) {
          this.taintBindingName(node.name);
        }
      }
      if (ts.isBindingElement(node)) {
        const variableDecl = findEnclosingVariableDeclaration(node);
        if (variableDecl?.initializer && isUntrustedInputText(variableDecl.initializer.getText(this.sourceFile))) {
          if (ts.isIdentifier(node.name)) {
            this.taintedDeclarations.add(node);
          }
        }
      }
    });
  }

  private propagateThroughAliases(): void {
    // One pass: if `const x = y;` and `y` resolves to a tainted declaration, taint `x`.
    // No fixed-point because we deliberately stay shallow — tighter scope, fewer FPs.
    ASTVisitor.visit(this.sourceFile, (node) => {
      if (!ts.isVariableDeclaration(node) || !node.initializer) return;

      if (this.isLikelyValidator(node.initializer)) {
        // Detaint the binding — including any BindingElements inside an object/array
        // destructuring pattern.
        this.markValidated(node);
        return;
      }

      if (this.isTainted(node.initializer)) {
        this.taintBindingName(node.name);
      }
    });
  }

  private taintBindingName(name: ts.BindingName): void {
    if (ts.isIdentifier(name)) {
      const decl = findEnclosingDeclaration(name);
      if (decl) this.taintedDeclarations.add(decl);
      return;
    }
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      name.elements.forEach((element) => {
        if (ts.isBindingElement(element)) {
          this.taintedDeclarations.add(element);
        }
      });
    }
  }

  private resolveIdentifierToDeclaration(identifier: ts.Identifier): ts.Node | undefined {
    // Walk enclosing scopes bottom-up. The FIRST declaration of `identifier.text` we
    // find in an enclosing scope's body wins. This emulates JavaScript lexical scoping
    // closely enough for taint without setting up a full TypeChecker.
    const candidates = this.declarationsByName.get(identifier.text);
    if (!candidates || candidates.length === 0) return undefined;
    if (candidates.length === 1) return candidates[0];

    // With multiple candidates, prefer the closest enclosing one.
    let best: ts.Node | undefined;
    let bestDepth = -1;
    for (const candidate of candidates) {
      if (!isAncestorOf(candidate, identifier)) continue;
      const depth = nodeDepth(candidate);
      if (depth > bestDepth) {
        best = candidate;
        bestDepth = depth;
      }
    }
    return best ?? candidates[0];
  }

  private isLikelyValidator(node: ts.Expression): boolean {
    if (!ts.isCallExpression(node)) return false;

    const expr = node.expression;
    if (ts.isPropertyAccessExpression(expr)) {
      const receiverName = ts.isIdentifier(expr.expression) ? expr.expression.text : '';
      const methodName = expr.name.text;
      // JSON.parse is NOT a validator — never detaint via JSON.parse.
      if (receiverName === 'JSON') return false;
      // Common validator-shape method calls. `parse`/`safeParse` cover zod/valibot;
      // `validate` covers ajv/io-ts/class-validator; `sanitize`/`escape` cover dompurify/xss.
      if (/^(parse|safeParse|validate|validateSync|sanitize|escape|allow|pick|omit|stripUnknown)$/.test(methodName)) {
        return true;
      }
    }

    const callee = expr.getText(this.sourceFile);
    return /joi|yup|zod|valibot|ajv|class-?validator|typebox|io-ts|whitelist|allowlist/i.test(callee);
  }
}

function findEnclosingVariableDeclaration(node: ts.Node): ts.VariableDeclaration | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isVariableDeclaration(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function findEnclosingDeclaration(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isVariableDeclaration(current) || ts.isBindingElement(current) || ts.isParameter(current)) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}

function isAncestorOf(possibleAncestor: ts.Node, descendant: ts.Node): boolean {
  let current: ts.Node | undefined = descendant.parent;
  while (current) {
    if (current === possibleAncestor) return true;
    // Climb past the declaration to its scope; once we leave the scope chain stop.
    current = current.parent;
  }
  return false;
}

function nodeDepth(node: ts.Node): number {
  let depth = 0;
  let current: ts.Node | undefined = node;
  while (current) {
    depth += 1;
    current = current.parent;
  }
  return depth;
}
