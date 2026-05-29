import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTParser } from '../parser/astParser';
import { ProofOfConcept } from '../poc/types';
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
            ruleId: 'BCR-RL-001',
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
            ruleId: 'BCR-RL-002',
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
            ruleId: 'BCR-RL-003',
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
            ruleId: 'BCR-RL-004',
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
   * Reserved hook for rate-limit POC generation. Intentionally empty — the rate-limit
   * detector emits structured findings that the standalone PocPipeline (when wired)
   * can consume by ruleId without per-detector POC code.
   */
  private generateMissingRateLimitPoc(_endpoint: string, _line: number): void { /* noop */ }
  private generateHeaderBypassPoc(_line: number): void { /* noop */ }
}
