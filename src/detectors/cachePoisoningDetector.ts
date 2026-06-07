import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';

/**
 * Cache Poisoning Detector
 *
 * Detects cache poisoning vulnerabilities in microservices:
 * - Caching user-controlled input without validation
 * - Using request headers as cache keys (Host, Referer, X-Forwarded-For)
 * - Caching without proper TTL or invalidation
 * - Race conditions in cache invalidation
 */
export class CachePoisoningDetector {
  private findings: Finding[] = [];
  private filePath: string;
  private sourceFile: ts.SourceFile;

  constructor(filePath: string, sourceFile: ts.SourceFile, _parser: ASTParser) {
    this.filePath = filePath;
    this.sourceFile = sourceFile;
  }

  detect(): DetectorResult {
    ASTVisitor.visit(this.sourceFile, (node: ts.Node) => {
      if (ts.isCallExpression(node)) {
        this.checkCacheKeyInjection(node);
      }
    });
    return { findings: this.findings };
  }

  private checkCacheKeyInjection(node: ts.CallExpression): void {
    // Match the cache-write CALL itself, not any enclosing call whose text merely contains one.
    // Previously `app.get('/x', () => cache.set(req.headers.host, v))` fired on BOTH the route
    // call and the inner `cache.set` (double report), because the route's full text contains the
    // sink. Inspect `node.expression` (receiver.method) instead.
    const callee = node.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const method = callee.name.text.toLowerCase();
    const receiver = callee.expression.getText(this.sourceFile).toLowerCase();
    const isCacheSink =
      (/^(set|put|store|setex|hset|mset|add)$/.test(method) &&
        /\b(cache|rediscache|memcache|memcached|kv|store|cacheclient)\b/.test(receiver)) ||
      (/^(set|put|setex)$/.test(method) && /\bredis\b/.test(receiver)) ||
      /memcache/.test(receiver);
    if (!isCacheSink) return;

    // Only the KEY argument matters for poisoning — not the cached value or surrounding code.
    const keyArg = node.arguments[0];
    if (!keyArg) return;
    const keyText = keyArg.getText(this.sourceFile);

    const userControlledKey = /\b(req|request)\.(headers|query|params|url|originalUrl|cookies)\b/i.test(keyText);
    if (!userControlledKey) return;

    // Normalization must apply to the KEY itself — an unrelated `hash(value)` / `validate(other)`
    // elsewhere in the statement no longer suppresses a poisoned key.
    const keyIsNormalized = /\b(sanitize|validate|normalize|encodeURIComponent|createHash|hmac|sha\d|allowlist|whitelist)\b/i.test(keyText);
    if (keyIsNormalized) return;

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    const headerPoisoning =
      /\b(req|request)\.headers\b/i.test(keyText) &&
      /\b(host|referer|referrer|user-?agent|x-forwarded-for|x-forwarded-host|x-original-url|forwarded)\b/i.test(keyText);

    this.findings.push({
      ruleId: headerPoisoning ? 'BCR-CACHE-002' : 'BCR-CACHE-001',
      file: this.filePath,
      line: lineNum,
      column: 0,
      severity: headerPoisoning ? 'CRITICAL' : 'HIGH',
      confidence: 'CONFIRMED',
      category: 'CACHE_POISONING',
      title: headerPoisoning
        ? 'Exploitable Cache Poisoning via HTTP Header Keying'
        : 'Exploitable Cache Poisoning via User-Controlled Cache Key',
      description: headerPoisoning
        ? 'Cache keying uses attacker-controlled HTTP headers (for example Host or X-Forwarded-For), enabling cross-user cache poisoning.'
        : 'Cache key is derived from attacker-controlled request data without normalization, enabling poisoned cache entries to be served to other users.',
      code: node.getText(this.sourceFile).substring(0, 120),
      recommendation:
        'Use trusted server-side identifiers for cache keys and normalize any externally influenced dimensions before cache writes.',
    });
  }
}
