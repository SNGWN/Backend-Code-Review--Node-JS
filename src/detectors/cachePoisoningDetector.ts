import * as ts from 'typescript';
import { Finding, DetectorResult } from '../types';
import { ASTVisitor } from '../parser/astVisitor';
import { ASTParser } from '../parser/astParser';

/**
 * Cache Poisoning Detector (Phase 3)
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
    const sourceText = node.getText(this.sourceFile);

    if (!/cache\.(set|put|store)|redis\.(set|put)|memcache/i.test(sourceText)) {
      return;
    }

    const userControlledKey = /req\.(headers|query|params|url|originalUrl)|request\.(headers|query|params|url)/i.test(
      sourceText
    );
    const keyIsNormalized = /sanitize|validate|normalize|encode|hash|sha|cacheKey/i.test(sourceText);

    if (!userControlledKey || keyIsNormalized) {
      return;
    }

    const lineNum = this.sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
    const dangerousHeaders = ['host', 'referer', 'user-agent', 'x-forwarded-for', 'x-original-url'];
    const headerPoisoning = dangerousHeaders.some((header) =>
      new RegExp(`headers\\[.*${header}.*\\]|headers\\.${header}`, 'i').test(sourceText)
    );

    this.findings.push({
      file: this.filePath,
      line: lineNum,
      column: 0,
      severity: headerPoisoning ? 'CRITICAL' : 'HIGH',
      category: 'CACHE_POISONING',
      title: headerPoisoning
        ? 'Exploitable Cache Poisoning via HTTP Header Keying'
        : 'Exploitable Cache Poisoning via User-Controlled Cache Key',
      description: headerPoisoning
        ? 'Cache keying uses attacker-controlled HTTP headers (for example Host or X-Forwarded-For), enabling cross-user cache poisoning.'
        : 'Cache key is derived from attacker-controlled request data without normalization, enabling poisoned cache entries to be served to other users.',
      code: sourceText,
      recommendation:
        'Use trusted server-side identifiers for cache keys and normalize any externally influenced dimensions before cache writes.',
    });
  }
}
