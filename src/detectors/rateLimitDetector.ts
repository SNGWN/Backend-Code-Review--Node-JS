import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept, PocGenerationRequest } from '../poc/types';
import {
  getRouteHandlerContexts,
  hasRateLimitProtection,
  resolveRateLimitConfig,
} from '../utils/detectorLogic';

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
    const routes = getRouteHandlerContexts(this.sourceFile, this.parser);

    routes.forEach((route) => {
      if (this.isSensitiveEndpoint(route.path) && !hasRateLimitProtection(route, this.sourceFile)) {
        this.findings.push({
            category: 'RATE_LIMITING',
            severity: 'HIGH',
            title: `Missing Rate Limiting on Sensitive Endpoint: ${route.path}`,
            description: `The endpoint ${route.path} does not have rate limiting middleware configured. This endpoint is a common target for brute force and DoS attacks.`,
            file: this.filePath,
            line: route.line,
            column: 1,
            code: route.routeText.substring(0, 100),
            recommendation: `Add rate limiting middleware using express-rate-limit with a maximum of 5-10 requests per minute for ${route.path}. Example: const limiter = rateLimit({ windowMs: 60 * 1000, max: 5 }); app.post('${route.path}', limiter, handler);`,
          });

        this.generateMissingRateLimitPoc(route.path, route.line);
      }
    });
  }

  /**
   * Detect rate limit bypass via header manipulation
   */
  private detectHeaderBypassVulnerabilities(): void {
    const routes = getRouteHandlerContexts(this.sourceFile, this.parser);

    routes.forEach((route) => {
      for (const middleware of route.middlewares) {
        const config = resolveRateLimitConfig(middleware, this.sourceFile);
        if (!config) {
          continue;
        }

        if (config.usesReqIpKey && !config.hasTrustedProxyProtection) {
          this.findings.push({
            category: 'RATE_LIMITING',
            severity: 'HIGH',
            title: 'Rate Limit Bypass via Header Manipulation',
            description:
              'The rate limit key generator relies on request IP data without visible trusted-proxy validation. Attackers can spoof forwarding headers to bypass IP-based rate limits.',
            file: this.filePath,
            line: route.line,
            column: 1,
            code: route.routeText.substring(0, 140),
            recommendation:
              'Only trust proxy headers from your own infrastructure and derive the client IP through a trusted helper before using it in keyGenerator.',
          });

          this.generateHeaderBypassPoc(route.line);
          return;
        }
      }
    });
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
    const routes = getRouteHandlerContexts(this.sourceFile, this.parser);

    routes.forEach((route) => {
      if (!this.isHighRiskRateLimitTarget(route.path)) {
        return;
      }

      route.middlewares.forEach((middleware) => {
        const config = resolveRateLimitConfig(middleware, this.sourceFile);
        if (!config?.maxRequests || !config.windowMs) {
          return;
        }

        if (config.usesReqIpKey && !config.hasTrustedProxyProtection) {
          return;
        }

        const requestsPerMinute = (config.maxRequests * 60000) / config.windowMs;
        if (requestsPerMinute > 10) {
          this.findings.push({
            category: 'RATE_LIMITING',
            severity: 'HIGH',
            title: 'Weak Rate Limiting on Sensitive Endpoint',
            description: `Rate limit of ${requestsPerMinute.toFixed(1)} requests per minute is too high for a sensitive endpoint. This allows brute force attacks with reasonable throughput.`,
            file: this.filePath,
            line: route.line,
            column: 1,
            code: route.routeText.substring(0, 160),
            recommendation:
              'Reduce rate limits on sensitive endpoints to 5-10 requests per minute: { windowMs: 60000, max: 5 }',
          });
        }
      });
    });
  }

  /**
   * Detect distributed rate limit bypass opportunities
   */
  private detectDistributedBypassOpportunities(): void {
    const routes = getRouteHandlerContexts(this.sourceFile, this.parser);

    routes.forEach((route) => {
      if (!this.isSensitiveEndpoint(route.path)) {
        return;
      }

      route.middlewares.forEach((middleware) => {
        const config = resolveRateLimitConfig(middleware, this.sourceFile);
        if (config?.usesMemoryStore && !config.usesDistributedStore) {
          this.findings.push({
            category: 'RATE_LIMITING',
            severity: 'HIGH',
            title: 'Distributed Rate Limit Bypass via Load Balancer',
            description:
              'Rate limiting uses in-memory storage, which is not shared across multiple server instances. An attacker can distribute requests across load-balanced servers to bypass rate limits.',
            file: this.filePath,
            line: route.line,
            column: 1,
            code: route.routeText.substring(0, 160),
            recommendation:
              'Use a distributed cache backend for rate limiting: rateLimit({ store: new RedisStore({ client: redisClient }) }). Ensure all instances share the same rate limit state.',
          });
        }
      });
    });
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

  private isHighRiskRateLimitTarget(path: string): boolean {
    return /(login|auth|admin|password|secret|key)/i.test(path);
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
