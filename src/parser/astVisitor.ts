import * as ts from 'typescript';

export type NodeVisitor<T = void> = (node: ts.Node) => T | undefined;

export class ASTVisitor {
  /**
   * Iterative pre-order traversal. The previous implementation recursed via
   * `ts.forEachChild` and overflowed the JS call stack on deeply-nested ASTs
   * (e.g. 5000-deep ternary expressions, deeply chained method calls). The
   * iterative version uses a work stack and a child-collection helper, so depth
   * is bounded by heap rather than stack.
   */
  static visit(node: ts.Node, visitor: NodeVisitor): void {
    const stack: ts.Node[] = [node];
    while (stack.length > 0) {
      const current = stack.pop() as ts.Node;
      visitor(current);
      // Collect children, then push in reverse order to preserve pre-order semantics
      // (left-to-right child visit order). `forEachChild` itself is non-recursive at
      // the immediate-child level — it's the recursion in our visit() that overflowed.
      const children: ts.Node[] = [];
      ts.forEachChild(current, (child) => { children.push(child); });
      for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
    }
  }

  static visitAll(node: ts.Node, visitor: NodeVisitor): ts.Node[] {
    const results: ts.Node[] = [];

    ASTVisitor.visit(node, (child) => {
      const result = visitor(child);
      if (result !== undefined) {
        results.push(child);
      }
    });

    return results;
  }

  static findNodes(node: ts.Node, predicate: (n: ts.Node) => boolean): ts.Node[] {
    const results: ts.Node[] = [];
    // Iterative walk (same reasoning as `visit`).
    const stack: ts.Node[] = [node];
    while (stack.length > 0) {
      const current = stack.pop() as ts.Node;
      if (predicate(current)) {
        results.push(current);
      }
      const children: ts.Node[] = [];
      ts.forEachChild(current, (child) => { children.push(child); });
      for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
    }
    return results;
  }

  static findCallExpressions(node: ts.Node, functionName?: string): ts.CallExpression[] {
    const calls = ASTVisitor.findNodes(
      node,
      (n): n is ts.CallExpression => ts.isCallExpression(n)
    ) as ts.CallExpression[];

    if (!functionName) return calls;

    // Support qualified names like "Object.assign". Previously this matched only the
    // property-access *name*, so `findCallExpressions(node, 'Object.assign')` returned
    // every `.assign()` call and never the qualified form — BCR-MA-001 silently never fired.
    if (functionName.includes('.')) {
      const [expectedReceiver, expectedProp] = functionName.split('.');
      return calls.filter((call) => {
        if (!ts.isPropertyAccessExpression(call.expression)) return false;
        const receiver = call.expression.expression;
        const receiverName = ts.isIdentifier(receiver) ? receiver.text : '';
        return receiverName === expectedReceiver && call.expression.name.text === expectedProp;
      });
    }

    return calls.filter((call) => {
      if (ts.isIdentifier(call.expression)) {
        return call.expression.text === functionName;
      }
      if (ts.isPropertyAccessExpression(call.expression)) {
        return call.expression.name.text === functionName;
      }
      return false;
    });
  }

  static findVariableDeclarations(node: ts.Node, name?: string): ts.VariableDeclaration[] {
    const declarations = ASTVisitor.findNodes(
      node,
      (n): n is ts.VariableDeclaration => ts.isVariableDeclaration(n)
    ) as ts.VariableDeclaration[];

    if (!name) return declarations;

    return declarations.filter((decl) => {
      if (ts.isIdentifier(decl.name)) {
        return decl.name.text === name;
      }
      return false;
    });
  }

  static findFunctionDeclarations(node: ts.Node, name?: string): ts.FunctionDeclaration[] {
    const functions = ASTVisitor.findNodes(
      node,
      (n): n is ts.FunctionDeclaration => ts.isFunctionDeclaration(n)
    ) as ts.FunctionDeclaration[];

    if (!name) return functions;

    return functions.filter((func) => {
      return func.name && func.name.text === name;
    });
  }

  static getIdentifierName(node: ts.Node | undefined): string | null {
    if (!node) return null;

    if (ts.isIdentifier(node)) {
      return node.text;
    }

    if (ts.isPropertyAccessExpression(node)) {
      return node.name.text;
    }

    return null;
  }

  static getCallExpressionName(call: ts.CallExpression): string | null {
    if (ts.isIdentifier(call.expression)) {
      return call.expression.text;
    }

    if (ts.isPropertyAccessExpression(call.expression)) {
      return call.expression.name.text;
    }

    return null;
  }

  static getObjectProperties(node: ts.ObjectLiteralExpression): Map<string, ts.Expression> {
    const properties = new Map<string, ts.Expression>();

    node.properties.forEach((prop) => {
      if (ts.isPropertyAssignment(prop)) {
        let key = '';
        if (ts.isIdentifier(prop.name)) {
          key = prop.name.text;
        } else if (ts.isStringLiteral(prop.name)) {
          key = prop.name.text;
        }

        if (key) {
          properties.set(key, prop.initializer);
        }
      }
    });

    return properties;
  }

  static findPropertyAccessExpression(
    node: ts.Node,
    propertyName: string
  ): ts.PropertyAccessExpression[] {
    return ASTVisitor.findNodes(
      node,
      (n): n is ts.PropertyAccessExpression =>
        ts.isPropertyAccessExpression(n) && n.name.text === propertyName
    ) as ts.PropertyAccessExpression[];
  }
}
