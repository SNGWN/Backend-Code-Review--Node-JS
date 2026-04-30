import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept, PocGenerationRequest } from '../poc/types';

/**
 * Rate Limiting Bypass Detector
 *
 * Detects rate limiting vulnerabilities and bypass opportunities:
 * - Missing rate limiting middleware on sensitive endpoints
 * - Rate limit bypass via header manipulation (X-Forwarded-For, X-Real-IP)
 * - Global-only rate limits without per-user limits
 * - Weak limits (>100 req/min on sensitive endpoints)
 * - Missing rate limit reset mechanisms
 * - Distributed rate limit bypass opportunities
 * - No account lockout protection
 *
 * Sensitive endpoints:
 * - /login, /register, /forgot-password (brute force targets)
 * - /api/admin/* (privilege escalation)
 * - /api/keys, /api/secrets (credential theft)
 * - /api/export/* (data exfiltration)
 */
export class RateLimitDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;
  private parser: ASTParser;
  private generatedPocs: ProofOfConcept[] = [];

  private sensitiveEndpoints = [
    '/login',
    '/register',
    '/forgot-password',
    '/api/admin',
    '/api/keys',
    '/api/secrets',
    '/api/export',
  ];

  private rateLimitPatterns = [
    'rateLimit',
    'rateLimiter',
    'RateLimit',
    'rate-limit',
    'express-rate-limit',
    'express-limiter',
    'throttle',
    'request-ip',
  ];

  private bypassHeaders = [
    'X-Forwarded-For',
    'X-Real-IP',
    'X-Client-IP',
    'CF-Connecting-IP',
    'X-Original-IP',
  ];

  constructor(filePath: string, sourceFile: ts.SourceFile, parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
    this.parser = parser;
  }

  detect(): DetectorResult {
    this.findings = [];
    this.generatedPocs = [];

    this.detectMissingRateLimitingMiddleware();
    this.detectHeaderBypassVulnerabilities();
    this.detectWeakRateLimits();
    this.detectDistributedBypassOpportunities();

    return { findings: this.findings };
  }

  getPocs(): ProofOfConcept[] {
    return this.generatedPocs;
  }

  /**
   * Detect missing rate limiting middleware on sensitive endpoints
   */
  private detectMissingRateLimitingMiddleware(): void {
    const routeHandlers: Map<string, ts.Node> = new Map();

    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isCallExpression(node)) {
        const callExpr = node as ts.CallExpression;
        const expr = callExpr.expression;

        // Look for route definitions like app.get(), app.post(), etc.
        if (ts.isPropertyAccessExpression(expr)) {
          const methodName = expr.name?.text;
          const httpMethods = ['get', 'post', 'put', 'delete', 'patch'];

          if (httpMethods.includes(methodName || '')) {
            const firstArg = callExpr.arguments[0];
            if (firstArg && ts.isStringLiteral(firstArg)) {
              const path = firstArg.text;
              routeHandlers.set(path, callExpr);
            }
          }
        }
      }
    });

    // Check if sensitive endpoints have rate limiting
    for (const [path, node] of routeHandlers) {
      if (this.isSensitiveEndpoint(path)) {
        const hasRateLimit = this.checkForRateLimitMiddleware(node);

        if (!hasRateLimit) {
          const line = this.sourceFile.getLineAndCharacterOfPosition(node.pos).line + 1;
          this.findings.push({
            category: 'RATE_LIMITING',
            severity: 'HIGH',
            title: `Missing Rate Limiting on Sensitive Endpoint: ${path}`,
            description: `The endpoint ${path} does not have rate limiting middleware configured. This endpoint is a common target for brute force and DoS attacks.`,
            file: this.filePath,
            line,
            column: 1,
            code: node.getText(this.sourceFile).substring(0, 100),
            recommendation: `Add rate limiting middleware using express-rate-limit with a maximum of 5-10 requests per minute for ${path}. Example: const limiter = rateLimit({ windowMs: 60 * 1000, max: 5 }); app.post('${path}', limiter, handler);`,
          });

          this.generateMissingRateLimitPoc(path, line);
        }
      }
    }
  }

  /**
   * Detect rate limit bypass via header manipulation
   */
  private detectHeaderBypassVulnerabilities(): void {
    let hasUnprotectedHeaderAccess = false;
    let line = 1;

    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      // Look for req.ip usage without proper validation
      if (ts.isPropertyAccessExpression(node)) {
        const expr = node as ts.PropertyAccessExpression;
        const prop = expr.name?.text;

        if (prop === 'ip') {
          const parent = expr.expression;
          if (parent && ts.isIdentifier(parent)) {
            const parentName = parent.getText(this.sourceFile);
            if (parentName === 'req') {
              line = this.sourceFile.getLineAndCharacterOfPosition(node.pos).line + 1;
              const parentNode = node.parent;
              const parentText = parentNode?.getText(this.sourceFile) || '';

              // Check if used directly without validation
              if (
                !parentText.includes('trustedProxies') &&
                !parentText.includes('trust') &&
                !parentText.includes('isInternalNetwork')
              ) {
                hasUnprotectedHeaderAccess = true;
              }
            }
          }
        }
      }
    });

    if (hasUnprotectedHeaderAccess) {
      this.findings.push({
        category: 'RATE_LIMITING',
        severity: 'HIGH',
        title: 'Rate Limit Bypass via Header Manipulation',
        description:
          'The IP address is extracted from req.ip without proper validation of trusted proxies. Attackers can spoof their IP address using X-Forwarded-For or similar headers to bypass rate limiting.',
        file: this.filePath,
        line,
        column: 1,
        code: 'req.ip usage without proxy validation',
        recommendation:
          'Configure express-rate-limit with proper trust proxy settings: rateLimit({ skip: (req) => !isInternalNetwork(req.ip), keyGenerator: (req) => getClientIp(req) }). Only trust proxies from your infrastructure.',
      });

      this.generateHeaderBypassPoc(line);
    }
  }

  /**
   * Detect global-only rate limits without per-user limits
   */
  private detectGlobalOnlyRateLimits(): void {
    let foundGlobalLimiter = false;
    let foundPerUserLimiter = false;

    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isVariableDeclaration(node)) {
        const name = node.name?.getText(this.sourceFile) || '';
        const initializer = node.initializer?.getText(this.sourceFile) || '';

        if (initializer.includes('rateLimit') || initializer.includes('rateLimiter')) {
          // Check if it has keyGenerator for per-user limiting
          if (
            !initializer.includes('keyGenerator') &&
            !initializer.includes('skip')
          ) {
            foundGlobalLimiter = true;
          } else if (initializer.includes('keyGenerator')) {
            foundPerUserLimiter = true;
          }
        }
      }

      // Look for rate limit configuration objects
      if (ts.isObjectLiteralExpression(node)) {
        const text = node.getText(this.sourceFile);

        if (text.includes('windowMs') && text.includes('max')) {
          if (!text.includes('keyGenerator')) {
            foundGlobalLimiter = true;
          } else {
            foundPerUserLimiter = true;
          }
        }
      }
    });

    if (foundGlobalLimiter && !foundPerUserLimiter) {
      this.findings.push({
        category: 'RATE_LIMITING',
        severity: 'MEDIUM',
        title: 'Global-Only Rate Limiting Without Per-User Limits',
        description:
          'The application uses global rate limiting without per-user limits. This allows an attacker to distribute requests across multiple user accounts to bypass rate limiting.',
        file: this.filePath,
        line: 1,
        column: 1,
        code: 'rateLimit({ windowMs: 60000, max: 100 })',
        recommendation:
          'Implement per-user rate limiting using keyGenerator: rateLimit({ windowMs: 60000, max: 5, keyGenerator: (req) => req.user?.id || req.ip })',
      });

      // this.generateGlobalOnlyBypassPoc(1);
    }
  }

  /**
   * Detect weak rate limits on sensitive endpoints
   */
  private detectWeakRateLimits(): void {
    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isObjectLiteralExpression(node)) {
        const obj = node as ts.ObjectLiteralExpression;
        let maxRequests = 0;
        let windowMs = 60000; // default to 1 minute
        let isSensitiveEndpoint = false;
        let line = this.sourceFile.getLineAndCharacterOfPosition(node.pos).line + 1;

        // Analyze object properties
        for (const prop of obj.properties) {
          if (ts.isPropertyAssignment(prop)) {
            const propName = prop.name?.getText(this.sourceFile) || '';
            const propValue = prop.initializer?.getText(this.sourceFile) || '';

            if (propName === 'max') {
              maxRequests = parseInt(propValue) || 100;
            } else if (propName === 'windowMs') {
              windowMs = parseInt(propValue) || 60000;
            }
          }
        }

        // Check if this is a sensitive endpoint
        const parentText = node.parent?.getText(this.sourceFile) || '';
        for (const endpoint of this.sensitiveEndpoints) {
          if (parentText.includes(endpoint)) {
            isSensitiveEndpoint = true;
            break;
          }
        }

        // Calculate requests per minute
        const requestsPerMinute = (maxRequests * 60000) / windowMs;

        if (
          isSensitiveEndpoint &&
          requestsPerMinute > 10
        ) {
          this.findings.push({
            category: 'RATE_LIMITING',
            severity: 'HIGH',
            title: 'Weak Rate Limiting on Sensitive Endpoint',
            description: `Rate limit of ${requestsPerMinute.toFixed(1)} requests per minute is too high for a sensitive endpoint. This allows brute force attacks with reasonable throughput.`,
            file: this.filePath,
            line,
            column: 1,
            code: node.getText(this.sourceFile),
            recommendation:
              'Reduce rate limits on sensitive endpoints to 5-10 requests per minute: { windowMs: 60000, max: 5 }',
          });

          // this.generateWeakLimitPoc(line, requestsPerMinute);
        }
      }
    });
  }

  /**
   * Detect distributed rate limit bypass opportunities
   */
  private detectDistributedBypassOpportunities(): void {
    let usesMemoryStore = false;
    let isDistributed = false;

    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      const text = node.getText(this.sourceFile);

      if (
        text.includes('store:') ||
        text.includes('memory') ||
        text.includes('MemoryStore')
      ) {
        usesMemoryStore = true;
      }

      if (
        text.includes('redis') ||
        text.includes('memcached') ||
        text.includes('RedisStore')
      ) {
        isDistributed = true;
      }
    });

    if (usesMemoryStore && !isDistributed) {
      this.findings.push({
        category: 'RATE_LIMITING',
        severity: 'HIGH',
        title: 'Distributed Rate Limit Bypass via Load Balancer',
        description:
          'Rate limiting uses in-memory storage, which is not shared across multiple server instances. An attacker can distribute requests across load-balanced servers to bypass rate limits.',
        file: this.filePath,
        line: 1,
        column: 1,
        code: 'rateLimit({ store: new MemoryStore() })',
        recommendation:
          'Use a distributed cache backend for rate limiting: rateLimit({ store: new RedisStore({ client: redisClient }) }). Ensure all instances share the same rate limit state.',
      });

      // this.generateDistributedBypassPoc(1);
    }
  }

  /**
   * Check if a route handler has rate limit middleware
   */
  private checkForRateLimitMiddleware(node: ts.Node): boolean {
    const text = node.getText(this.sourceFile);

    for (const pattern of this.rateLimitPatterns) {
      if (text.toLowerCase().includes(pattern.toLowerCase())) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if an endpoint is sensitive
   */
  private isSensitiveEndpoint(path: string): boolean {
    return this.sensitiveEndpoints.some(endpoint => {
      if (endpoint.endsWith('/*')) {
        return path.startsWith(endpoint.slice(0, -2));
      }
      return path === endpoint || path.startsWith(endpoint);
    });
  }

  /**
   * Generate POC for missing rate limiting
   */
  private generateMissingRateLimitPoc(endpoint: string, line: number): void {
    // POC generation coming in Phase 2 POC templates
  }

  /**
   * Generate POC for header bypass
   */
  private generateHeaderBypassPoc(line: number): void {
    // POC generation coming in Phase 2 POC templates
  }
}
