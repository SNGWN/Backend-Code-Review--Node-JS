import * as ts from 'typescript';

export type NodeVisitor<T = void> = (node: ts.Node) => T | undefined;

export class ASTVisitor {
  static visit(node: ts.Node, visitor: NodeVisitor): void {
    visitor(node);
    ts.forEachChild(node, (child) => {
      ASTVisitor.visit(child, visitor);
    });
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

    const walk = (node: ts.Node) => {
      if (predicate(node)) {
        results.push(node);
      }
      ts.forEachChild(node, walk);
    };

    walk(node);
    return results;
  }

  static findCallExpressions(node: ts.Node, functionName?: string): ts.CallExpression[] {
    const calls = ASTVisitor.findNodes(
      node,
      (n): n is ts.CallExpression => ts.isCallExpression(n)
    ) as ts.CallExpression[];

    if (!functionName) return calls;

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
