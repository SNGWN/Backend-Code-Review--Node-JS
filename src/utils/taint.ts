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
/**
 * Same-file summary of a function: does it hand attacker-controlled data back to its caller?
 *   - `returnsUntrusted`  — the body returns an expression that reads an untrusted source
 *     directly (e.g. `return req.params.id`). The return value is tainted for ANY call.
 *   - `returnsParams`     — parameter indices that flow to a return (pass-through, e.g.
 *     `return x` / `return x.id`). The return value is tainted iff that argument is tainted.
 */
interface FunctionTaintSummary {
  returnsUntrusted: boolean;
  returnsParams: Set<number>;
}

export class TaintTracker {
  private taintedDeclarations = new Set<ts.Node>();
  /** name → declaration nodes the name might resolve to (for fast prefiltering). */
  private declarationsByName = new Map<string, ts.Node[]>();
  /** validation/sanitization markers — declarations passed through these are detainted. */
  private validatedDeclarations = new Set<ts.Node>();
  /** Per-function taint summaries, keyed by the function-like node. */
  private functionSummaries = new Map<ts.Node, FunctionTaintSummary>();
  /** Callable name (function decl, or const = arrow/fn-expr, or method) → its node. */
  private functionsByName = new Map<string, ts.Node[]>();

  constructor(private sourceFile: ts.SourceFile) {
    this.indexDeclarations();
    this.buildFunctionSummaries();
    this.seedFromUntrustedSources();
    // Framework-aware ingress: NestJS param decorators (@Body/@Param/@Query/@Args/...),
    // message-queue / event consumer callback payloads, and GraphQL resolver args. These are
    // the controller/middleware/consumer entry points where attacker data enters a service.
    this.seedFromFrameworkSources();
    this.propagateThroughAliases();
    // Inter-procedural pass: propagate taint across calls to local helper functions whose
    // summary says they return attacker-controlled data. Iterated to a small fixpoint so
    // chains (`const a = getId(req); const b = wrap(a);`) converge.
    this.propagateThroughLocalCalls();
  }

  /**
   * Seed taint from backend-framework ingress points that a plain `req.body` text match misses:
   *   - NestJS / type-graphql parameter decorators: `@Body()`, `@Param()`, `@Query()`,
   *     `@Headers()`, `@Req()`, `@Args()`, `@UploadedFile()` — the decorated parameter carries
   *     attacker-controlled data.
   *   - Message-queue / event-stream consumer callbacks: the first parameter of the handler
   *     passed to `.on()`, `.consume()`, `.subscribe()`, `eachMessage`, `process`, etc. is the
   *     delivered (attacker-influenced) payload.
   *   - Apollo-style GraphQL resolvers: the 2nd parameter (`args`) of a resolver function under
   *     a `Query`/`Mutation`/`Subscription`/`resolvers` object is user input.
   * These only ever produce a finding if the tainted value reaches a sink without validation, so
   * broad seeding here does not create noise on its own.
   */
  private seedFromFrameworkSources(): void {
    const SOURCE_DECORATORS = /^(Body|Param|Query|Headers|Req|Request|Args|UploadedFile|UploadedFiles|RawBody|Ip|Session|HostParam)$/;
    const CONSUMER_METHODS = /^(on|once|addEventListener|consume|subscribe|eachMessage|eachBatch|process|handle|receive)$/;

    ASTVisitor.visit(this.sourceFile, (node) => {
      // (1) Decorated parameters.
      if (ts.isParameter(node) && ts.isIdentifier(node.name)) {
        const decorators = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
        if (decorators) {
          for (const decorator of decorators) {
            const expr = ts.isCallExpression(decorator.expression) ? decorator.expression.expression : decorator.expression;
            const name = ts.isIdentifier(expr) ? expr.text : '';
            if (SOURCE_DECORATORS.test(name)) {
              this.taintedDeclarations.add(node);
              break;
            }
          }
        }
      }

      // (2) Consumer-callback payloads + (3) GraphQL resolver args.
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (CONSUMER_METHODS.test(method) && node.arguments.length > 0) {
          const callback = node.arguments[node.arguments.length - 1];
          if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) {
            const first = callback.parameters[0];
            if (first && ts.isIdentifier(first.name)) this.taintedDeclarations.add(first);
          }
        }
      }
    });

    // (3) Apollo-style resolvers: a function whose 2nd param is `args`/`input` and lives under a
    // `Query`/`Mutation`/`Subscription`/`resolvers` object literal key.
    ASTVisitor.visit(this.sourceFile, (node) => {
      if (!ts.isFunctionExpression(node) && !ts.isArrowFunction(node) && !ts.isMethodDeclaration(node)) return;
      const argsParam = node.parameters[1];
      if (!argsParam || !ts.isIdentifier(argsParam.name)) return;
      if (!/^(args|input|variables)$/.test(argsParam.name.text)) return;
      if (this.isUnderResolverObject(node)) this.taintedDeclarations.add(argsParam);
    });
  }

  /** True if `node` is a value under a `Query`/`Mutation`/`Subscription`/`resolvers` object key. */
  private isUnderResolverObject(node: ts.Node): boolean {
    let current: ts.Node | undefined = node.parent;
    let depth = 0;
    while (current && depth < 8) {
      if (ts.isPropertyAssignment(current)) {
        const key = current.name.getText(this.sourceFile).replace(/['"`]/g, '');
        if (/^(Query|Mutation|Subscription|resolvers|Resolvers)$/.test(key)) return true;
      }
      current = current.parent;
      depth += 1;
    }
    return false;
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
      if (ts.isIdentifier(current) && !isNameOnlyPosition(current)) {
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
      // Assignment (not just declaration): `let id; ... id = req.params.id`. The previous
      // version only seeded `const id = req.params.id`, missing the reassignment shape.
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left) &&
        isUntrustedInputText(node.right.getText(this.sourceFile))
      ) {
        const declaration = this.resolveIdentifierToDeclaration(node.left);
        if (declaration) this.taintedDeclarations.add(declaration);
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

      // A one-way transform of a tainted value (hash/encrypt/sign) yields a non-injectable
      // output — do not propagate taint to the binding.
      if (this.isOneWayTransform(node.initializer)) {
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
    // Walk enclosing scopes bottom-up. The FIRST declaration of `identifier.text` visible
    // from `identifier`'s scope wins. This emulates JavaScript lexical scoping closely
    // enough for taint without setting up a full TypeChecker.
    const candidates = this.declarationsByName.get(identifier.text);
    if (!candidates || candidates.length === 0) return undefined;
    if (candidates.length === 1) return candidates[0];

    // Prefer the candidate whose OWNING SCOPE is the innermost scope that also encloses the
    // identifier (proper shadowing). The previous version compared the declaration node
    // itself against the identifier with isAncestorOf — but a declaration is essentially
    // never an ancestor of a sibling usage, so every candidate was rejected and it silently
    // fell back to source-order-first. Comparing the declaration's *scope* is what makes
    // shadowing actually work.
    let best: ts.Node | undefined;
    let bestDepth = -1;
    for (const candidate of candidates) {
      const scope = enclosingScopeNode(candidate);
      if (!scope) continue;
      const visible = scope === this.sourceFile || isAncestorOf(scope, identifier);
      if (!visible) continue;
      const depth = nodeDepth(scope);
      if (depth > bestDepth) {
        best = candidate;
        bestDepth = depth;
      }
    }
    return best ?? candidates[0];
  }

  /**
   * Build a same-file taint summary for every function-like node, and index callables by
   * name so call sites can be resolved. Powers in-file inter-procedural taint.
   */
  private buildFunctionSummaries(): void {
    const summarize = (fn: ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration): void => {
      const params: string[] = [];
      fn.parameters.forEach((p) => {
        if (ts.isIdentifier(p.name)) params.push(p.name.text);
      });

      const returnExprs: ts.Expression[] = [];
      if (ts.isArrowFunction(fn) && fn.body && !ts.isBlock(fn.body)) {
        // Expression-bodied arrow: `(x) => x.id` — the body IS the returned expression.
        returnExprs.push(fn.body);
      } else if (fn.body) {
        // Collect every `return <expr>` without descending into nested functions (their
        // returns belong to a different summary).
        const collect = (node: ts.Node): void => {
          if (node !== fn && isFunctionLike(node)) return;
          if (ts.isReturnStatement(node) && node.expression) returnExprs.push(node.expression);
          ts.forEachChild(node, collect);
        };
        ts.forEachChild(fn.body, collect);
      }

      let returnsUntrusted = false;
      const returnsParams = new Set<number>();
      for (const expr of returnExprs) {
        const text = expr.getText(this.sourceFile);
        if (isUntrustedInputText(text)) returnsUntrusted = true;
        params.forEach((paramName, index) => {
          if (referencesIdentifierName(expr, paramName)) returnsParams.add(index);
        });
      }

      this.functionSummaries.set(fn, { returnsUntrusted, returnsParams });
    };

    ASTVisitor.visit(this.sourceFile, (node) => {
      if (ts.isFunctionDeclaration(node)) {
        if (node.name) this.addCallable(node.name.text, node);
        summarize(node);
      } else if (ts.isMethodDeclaration(node)) {
        if (ts.isIdentifier(node.name)) this.addCallable(node.name.text, node);
        summarize(node);
      } else if (ts.isFunctionExpression(node) || ts.isArrowFunction(node)) {
        summarize(node);
        // `const handler = (x) => ...` / `const f = function () {}` — index by the bound name.
        const parent = node.parent;
        if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
          this.addCallable(parent.name.text, node);
        }
      }
    });
  }

  private addCallable(name: string, node: ts.Node): void {
    const existing = this.functionsByName.get(name) ?? [];
    existing.push(node);
    this.functionsByName.set(name, existing);
  }

  /**
   * Propagate taint through calls to LOCAL helper functions. For `const x = helper(args)`:
   *   - if helper returns an untrusted source it reads internally → taint x;
   *   - if helper passes a parameter through to its return and that argument is tainted → taint x.
   * External/library calls are deliberately NOT propagated here (that path is handled by the
   * text-based alias pass), which keeps one-way transforms like `hash(req.body)` from tainting
   * their output. Iterated to a small fixpoint so multi-hop helper chains converge.
   */
  private propagateThroughLocalCalls(): void {
    for (let pass = 0; pass < 5; pass++) {
      let changed = false;
      ASTVisitor.visit(this.sourceFile, (node) => {
        if (!ts.isVariableDeclaration(node) || !node.initializer) return;
        if (!ts.isCallExpression(node.initializer)) return;
        const decl = node;
        if (this.declIsTainted(decl) || this.validatedDeclarations.has(decl)) return;
        if (this.isLikelyValidator(node.initializer)) return;

        const fns = this.resolveCallTarget(node.initializer);
        if (fns.length === 0) return;

        const args = node.initializer.arguments;
        for (const fn of fns) {
          const summary = this.functionSummaries.get(fn);
          if (!summary) continue;
          if (summary.returnsUntrusted) {
            this.taintBindingName(node.name);
            changed = true;
            break;
          }
          let propagated = false;
          summary.returnsParams.forEach((index) => {
            const arg = args[index];
            if (arg && this.isTainted(arg)) propagated = true;
          });
          if (propagated) {
            this.taintBindingName(node.name);
            changed = true;
            break;
          }
        }
      });
      if (!changed) break;
    }
  }

  /** Resolve a call expression's callee to local function node(s), if any. */
  private resolveCallTarget(call: ts.CallExpression): ts.Node[] {
    const expr = call.expression;
    let name: string | undefined;
    if (ts.isIdentifier(expr)) {
      name = expr.text;
    } else if (ts.isPropertyAccessExpression(expr)) {
      // `this.getId(...)` / `obj.getId(...)` — resolve by method name (heuristic).
      name = expr.name.text;
    }
    if (!name) return [];
    return this.functionsByName.get(name) ?? [];
  }

  /** True if the declaration node (or any binding element under it) is tainted. */
  private declIsTainted(decl: ts.Node): boolean {
    if (this.taintedDeclarations.has(decl)) return true;
    if (ts.isVariableDeclaration(decl) && (ts.isObjectBindingPattern(decl.name) || ts.isArrayBindingPattern(decl.name))) {
      return decl.name.elements.some((el) => ts.isBindingElement(el) && this.taintedDeclarations.has(el));
    }
    return false;
  }

  private isLikelyValidator(node: ts.Expression): boolean {
    if (!ts.isCallExpression(node)) return false;

    const expr = node.expression;
    if (ts.isPropertyAccessExpression(expr)) {
      const receiverName = ts.isIdentifier(expr.expression) ? expr.expression.text : '';
      const methodName = expr.name.text;
      // JSON.parse is NOT a validator — never detaint via JSON.parse.
      if (receiverName === 'JSON') return false;
      // A validator-shaped method called ON the tainted value itself is not validation —
      // `req.body.parse()` / `userInput.validate()` operate on attacker data and return
      // attacker data. Only detaint when the RECEIVER (the schema/validator) is not tainted.
      if (this.isTainted(expr.expression)) return false;
      // `pick`/`omit`/`allow` were removed: they whitelist FIELD NAMES but the surviving field
      // VALUES are still attacker-controlled, so they sanitize mass-assignment but NOT injection.
      // `parse`/`safeParse` cover zod/valibot; `validate` covers ajv/io-ts/class-validator;
      // `sanitize`/`escape` cover dompurify/xss.
      if (/^(parse|safeParse|validate|validateSync|sanitize|escape|stripUnknown)$/.test(methodName)) {
        return true;
      }
    }

    const callee = expr.getText(this.sourceFile);
    return /joi|yup|zod|valibot|ajv|class-?validator|typebox|io-ts|whitelist|allowlist/i.test(callee);
  }

  /**
   * One-way transforms whose OUTPUT is not attacker-controllable in the injection sense, even
   * though a tainted value flows IN. Hashing/HMAC/encryption/signing/random derivation all
   * destroy the attacker's ability to choose the output bytes, so the result should not carry
   * injection taint. Fixes taint leaking through `const h = hash(req.body.x)`.
   */
  private isOneWayTransform(node: ts.Expression): boolean {
    if (!ts.isCallExpression(node)) return false;
    const name = ts.isPropertyAccessExpression(node.expression)
      ? node.expression.name.text
      : ts.isIdentifier(node.expression)
        ? node.expression.text
        : '';
    return /^(hash|hashSync|createHash|createHmac|hmac|encrypt|sign|digest|bcrypt|scrypt|pbkdf2|pbkdf2Sync|argon2|randomBytes|randomUUID|uuid|genSalt|genSaltSync)$/i.test(name);
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

/**
 * True when `id` occupies a position where it names a property rather than referencing a value:
 * the `.name` of a property access (`foo.host`), an object-literal key (`{ host: ... }`), the
 * property name of a binding element, or a qualified-name right side. Resolving these as variable
 * references is wrong — e.g. the key `host` in `z.object({ host: ... })` is not the `host` local.
 * Shorthand object properties (`{ host }`, where the name IS a value reference) are NOT skipped.
 */
function isNameOnlyPosition(id: ts.Identifier): boolean {
  const parent = id.parent;
  if (!parent) return false;
  if (ts.isPropertyAccessExpression(parent) && parent.name === id) return true;
  if (ts.isPropertyAssignment(parent) && parent.name === id) return true;
  if (ts.isBindingElement(parent) && parent.propertyName === id) return true;
  if (ts.isQualifiedName(parent) && parent.right === id) return true;
  if (ts.isMethodDeclaration(parent) && parent.name === id) return true;
  return false;
}

function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

/**
 * Nearest scope-introducing ancestor of a declaration: the function/block/loop/catch/source
 * that owns the binding. Used to resolve lexical shadowing.
 */
function enclosingScopeNode(decl: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = decl.parent;
  while (current) {
    if (
      isFunctionLike(current) ||
      ts.isBlock(current) ||
      ts.isSourceFile(current) ||
      ts.isForStatement(current) ||
      ts.isForOfStatement(current) ||
      ts.isForInStatement(current) ||
      ts.isCatchClause(current) ||
      ts.isCaseBlock(current) ||
      ts.isModuleBlock(current)
    ) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}

/** True if `name` appears as an Identifier anywhere within `node`'s subtree. */
function referencesIdentifierName(node: ts.Node, name: string): boolean {
  let found = false;
  const visit = (current: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(current) && current.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(current, visit);
  };
  visit(node);
  return found;
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
