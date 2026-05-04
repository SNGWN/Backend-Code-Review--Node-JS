import * as ts from 'typescript';
import { ASTParser } from '../parser/astParser';
import { ASTVisitor } from '../parser/astVisitor';
import { HTTP_METHODS } from './constants';

export interface RouteHandlerContext {
  callExpression: ts.CallExpression;
  method: string;
  path: string;
  middlewares: ts.Expression[];
  middlewareText: string;
  handler?: ts.Expression;
  routeText: string;
  handlerText: string;
  line: number;
}

export interface RateLimitConfig {
  maxRequests?: number;
  windowMs?: number;
  hasKeyGenerator: boolean;
  usesReqIpKey: boolean;
  hasTrustedProxyProtection: boolean;
  usesMemoryStore: boolean;
  usesDistributedStore: boolean;
}

const SENSITIVE_ROUTE_PATTERN =
  /(admin|profile|settings|role|permission|secret|key|export|payment|billing|invoice|order|password|forgot|reset|token|auth|login|register|user)/i;
const SENSITIVE_HANDLER_PATTERN =
  /(delete|destroy|remove|update|save\(|insert|create|grant|assign|role|permission|admin|export|secret|apikey|token|password|billing|payment)/i;
const AUTH_CONTEXT_PATTERN =
  /(authmiddleware|authorizationmiddleware|requireauth|ensureauth|passport\.authenticate|jwt\.verify|verifytoken|validatetoken|authenticate|protect|guard|req\.user|currentuser|res\.locals\.user|ctx\.state\.user|request\.user)/i;
const AUTHZ_CONTEXT_PATTERN =
  /(authorize|authorization|permission|role|scope|forbidden|status\(403\)|statusCode\s*=\s*403|hasrole|haspermission|canaccess|accessdenied|isadmin)/i;
const OWNERSHIP_RESOURCE_PATTERN =
  /(owner|ownerid|userid|user_id|accountid|tenantid|organizationid|orgid|resource\.userid|resource\.ownerid)/i;
const RATE_LIMIT_NAME_PATTERN = /(ratelimit|ratelimiter|limiter|throttle|throttler)/i;
const UNTRUSTED_INPUT_PATTERN =
  /(req|request)\.(body|query|params|headers|cookies)|ctx\.request|userinput|userdata|payload|socket\.on\(|window\.|document\./i;
const VALIDATION_BOUNDARY_PATTERN =
  /(joi|yup|zod|validator|express-validator|safeparse|schema|allowlist|whitelist|sanitize|pick\(|omit\(|stripunknown|strict\()/i;

export function getRouteHandlerContexts(
  sourceFile: ts.SourceFile,
  parser: ASTParser
): RouteHandlerContext[] {
  const routes: RouteHandlerContext[] = [];

  ASTVisitor.findCallExpressions(sourceFile).forEach((callExpression) => {
    if (!ts.isPropertyAccessExpression(callExpression.expression)) {
      return;
    }

    const method = callExpression.expression.name.text.toLowerCase();
    if (!HTTP_METHODS.includes(method)) {
      return;
    }

    const pathArgument = callExpression.arguments[0];
    const path = getRoutePath(pathArgument, sourceFile);
    if (!path) {
      return;
    }

    const line = parser.getLineAndColumn(callExpression.getStart()).line;
    const handler = callExpression.arguments[callExpression.arguments.length - 1];
    const middlewares =
      callExpression.arguments.length > 2
        ? callExpression.arguments.slice(1, callExpression.arguments.length - 1)
        : [];

    routes.push({
      callExpression,
      method,
      path,
      middlewares,
      middlewareText: middlewares.map((middleware) => getResolvedNodeText(middleware, sourceFile)).join('\n'),
      handler,
      routeText: callExpression.getText(sourceFile),
      handlerText: handler ? getResolvedNodeText(handler, sourceFile) : '',
      line,
    });
  });

  return routes;
}

export function isSensitiveRouteContext(route: RouteHandlerContext): boolean {
  const normalizedPath = route.path.toLowerCase();
  const handlerText = route.handlerText.toLowerCase();

  if (['delete', 'put', 'patch'].includes(route.method)) {
    return true;
  }

  if (SENSITIVE_ROUTE_PATTERN.test(normalizedPath)) {
    return true;
  }

  return (
    SENSITIVE_HANDLER_PATTERN.test(handlerText) &&
    /(req\.(body|params|query)|db\.|model\.|repository\.|service\.|res\.json)/i.test(handlerText)
  );
}

export function hasAuthenticationProtection(route: RouteHandlerContext): boolean {
  const text = [route.routeText, route.middlewareText, route.handlerText]
    .filter(Boolean)
    .join('\n')
    .toLowerCase();

  return AUTH_CONTEXT_PATTERN.test(text);
}

export function hasAuthorizationProtection(route: RouteHandlerContext | string): boolean {
  const text = typeof route === 'string'
    ? route.toLowerCase()
    : [route.routeText, route.middlewareText, route.handlerText].filter(Boolean).join('\n').toLowerCase();

  return hasOwnershipCheck(text) || (AUTH_CONTEXT_PATTERN.test(text) && AUTHZ_CONTEXT_PATTERN.test(text));
}

export function hasOwnershipCheck(text: string): boolean {
  const normalizedText = text.toLowerCase();
  const hasIdentity = /(req\.user|currentuser|res\.locals\.user|ctx\.state\.user|request\.user)/.test(
    normalizedText
  );
  const hasProtectedResource = OWNERSHIP_RESOURCE_PATTERN.test(normalizedText);
  const hasDecision =
    /(===|!==|==|!=|forbidden|status\(403\)|return\s+res\.status\(403\)|throw new forbidden)/.test(
      normalizedText
    ) || /(hasrole|haspermission|canaccess|authorize)/.test(normalizedText);

  return hasIdentity && hasProtectedResource && hasDecision;
}

export function isUserControlledExpression(
  expression: ts.Expression,
  sourceFile: ts.SourceFile
): boolean {
  const text = expression.getText(sourceFile).toLowerCase();
  if (/(req|request)\.(params|query|body|headers|cookies)/.test(text)) {
    return true;
  }

  if (ts.isIdentifier(expression)) {
    const declarations = ASTVisitor.findVariableDeclarations(sourceFile, expression.text);
    return declarations.some((declaration) => {
      const initializerText = declaration.initializer?.getText(sourceFile).toLowerCase() || '';
      return /(req|request)\.(params|query|body|headers|cookies)/.test(initializerText);
    });
  }

  return false;
}

export function getEnclosingScopeText(node: ts.Node, sourceFile: ts.SourceFile): string {
  let current: ts.Node | undefined = node;

  while (current) {
    if (
      ts.isFunctionDeclaration(current) ||
      ts.isFunctionExpression(current) ||
      ts.isArrowFunction(current) ||
      ts.isMethodDeclaration(current) ||
      ts.isCallExpression(current)
    ) {
      return current.getText(sourceFile).toLowerCase();
    }

    current = current.parent;
  }

  return node.getText(sourceFile).toLowerCase();
}

export function isUntrustedInputText(text: string): boolean {
  return UNTRUSTED_INPUT_PATTERN.test(text);
}

export function hasValidationBoundary(node: ts.Node, sourceFile: ts.SourceFile): boolean {
  return VALIDATION_BOUNDARY_PATTERN.test(getEnclosingScopeText(node, sourceFile));
}

export function hasRateLimitProtection(
  route: RouteHandlerContext,
  sourceFile: ts.SourceFile
): boolean {
  return route.middlewares.some((middleware) => resolveRateLimitConfig(middleware, sourceFile) !== null);
}

export function resolveRateLimitConfig(
  expression: ts.Expression,
  sourceFile: ts.SourceFile
): RateLimitConfig | null {
  const resolved = resolveExpression(expression, sourceFile);

  if (ts.isCallExpression(resolved)) {
    const callName = ASTVisitor.getCallExpressionName(resolved)?.toLowerCase() || '';
    if (!RATE_LIMIT_NAME_PATTERN.test(callName)) {
      return null;
    }

    const configArgument = resolved.arguments.find((argument) => ts.isObjectLiteralExpression(argument));
    if (!configArgument || !ts.isObjectLiteralExpression(configArgument)) {
      return {
        hasKeyGenerator: false,
        usesReqIpKey: false,
        hasTrustedProxyProtection: false,
        usesMemoryStore: false,
        usesDistributedStore: false,
      };
    }

      return readRateLimitConfig(configArgument, resolved.getText(sourceFile), sourceFile);
    }

  if (ts.isObjectLiteralExpression(resolved)) {
    return readRateLimitConfig(resolved, resolved.getText(sourceFile), sourceFile);
  }

  return null;
}

function readRateLimitConfig(
  objectLiteral: ts.ObjectLiteralExpression,
  outerText: string,
  sourceFile: ts.SourceFile
): RateLimitConfig {
  const properties = ASTVisitor.getObjectProperties(objectLiteral);
  const keyGenerator = properties.get('keyGenerator');
  const store = properties.get('store');

  const keyGeneratorText = keyGenerator?.getText(sourceFile).toLowerCase() || '';
  const storeText = store?.getText(sourceFile).toLowerCase() || '';

  return {
    maxRequests: readNumericExpression(properties.get('max')),
    windowMs: readNumericExpression(properties.get('windowMs')),
    hasKeyGenerator: Boolean(keyGenerator),
    usesReqIpKey:
      /req\.ip|request\.ip|x-forwarded-for|x-real-ip|x-client-ip|cf-connecting-ip/.test(
        keyGeneratorText
      ),
    hasTrustedProxyProtection:
      /trustedproxies|trust proxy|isinternalnetwork|getclientip|proxy-addr/.test(keyGeneratorText),
    usesMemoryStore: /memorystore|memory/.test(storeText || outerText.toLowerCase()),
    usesDistributedStore: /redis|redisstore|memcached|cluster|storeclient/.test(storeText),
  };
}

function readNumericExpression(expression: ts.Expression | undefined): number | undefined {
  if (!expression) {
    return undefined;
  }

  if (ts.isNumericLiteral(expression)) {
    return Number(expression.text);
  }

  if (ts.isPrefixUnaryExpression(expression)) {
    const value = readNumericExpression(expression.operand);
    if (value === undefined) {
      return undefined;
    }

    return expression.operator === ts.SyntaxKind.MinusToken ? -value : value;
  }

  if (ts.isParenthesizedExpression(expression)) {
    return readNumericExpression(expression.expression);
  }

  if (ts.isBinaryExpression(expression)) {
    const left = readNumericExpression(expression.left);
    const right = readNumericExpression(expression.right);

    if (left === undefined || right === undefined) {
      return undefined;
    }

    switch (expression.operatorToken.kind) {
      case ts.SyntaxKind.AsteriskToken:
        return left * right;
      case ts.SyntaxKind.SlashToken:
        return right === 0 ? undefined : left / right;
      case ts.SyntaxKind.PlusToken:
        return left + right;
      case ts.SyntaxKind.MinusToken:
        return left - right;
      default:
        return undefined;
    }
  }

  return undefined;
}

function getRoutePath(argument: ts.Expression | undefined, sourceFile: ts.SourceFile): string | null {
  if (!argument) {
    return null;
  }

  if (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument)) {
    return argument.text;
  }

  return argument.getText(sourceFile).replace(/^['"`]|['"`]$/g, '');
}

function getResolvedNodeText(expression: ts.Expression, sourceFile: ts.SourceFile): string {
  return resolveExpression(expression, sourceFile).getText(sourceFile);
}

function resolveExpression(expression: ts.Expression, sourceFile: ts.SourceFile): ts.Node {
  if (ts.isIdentifier(expression)) {
    const declaration = resolveIdentifierDeclaration(expression.text, sourceFile);
    if (declaration) {
      if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
        return declaration.initializer;
      }

      return declaration;
    }
  }

  return expression;
}

function resolveIdentifierDeclaration(
  identifier: string,
  sourceFile: ts.SourceFile
): ts.Declaration | undefined {
  const variableDeclaration = ASTVisitor.findVariableDeclarations(sourceFile, identifier)[0];
  if (variableDeclaration) {
    return variableDeclaration;
  }

  const functionDeclaration = ASTVisitor.findFunctionDeclarations(sourceFile, identifier)[0];
  if (functionDeclaration) {
    return functionDeclaration;
  }

  return undefined;
}
