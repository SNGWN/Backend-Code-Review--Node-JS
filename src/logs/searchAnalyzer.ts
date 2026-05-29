import { KibanaClient, FreeTextSearchOptions, LogHit } from './kibanaClient';
import { buildRedactedExcerpt } from './logRules';

/** Mask the user's query string the same way excerpts mask matched values. */
function maskQuery(query: string): string {
  return query.replace(/("[^"]+"|[^\s()]{4,})/g, (token) => {
    if (token.length <= 4) return '*'.repeat(token.length);
    return token.slice(0, 2) + '*'.repeat(token.length - 4) + token.slice(-2);
  });
}

/**
 * Free-text search analyzer.
 *
 * Used by `--mode search`. Streams hits from Kibana matching a user-supplied
 * query, and returns each hit with:
 *   - the source document identity (`index`, `_id`, container, timestamp)
 *   - a Kibana Discover deep-link
 *   - a redacted excerpt around the matched term
 *
 * Why redact? The user already knows their query; what they need is to find
 * WHERE the term appears, not see it echoed back. If the user searched for a
 * PAN, replaying it in our report would be a PCI-DSS leak by the tool itself.
 */

export interface SearchHitResult {
  docId: string;
  index: string;
  timestamp: string;
  container?: string;
  kibanaUrl: string;
  excerpt: string;
}

export interface SearchReport {
  query: string;
  containerName?: string;
  fromIso: string;
  toIso: string;
  totalHits: number;
  hits: SearchHitResult[];
  truncated: boolean;
  durationMs: number;
}

export class SearchAnalyzer {
  constructor(private client: KibanaClient) {}

  async search(options: FreeTextSearchOptions): Promise<SearchReport> {
    const start = Date.now();
    const hits: SearchHitResult[] = [];
    let truncated = false;

    try {
      for await (const hit of this.client.searchFreeText(options)) {
        hits.push(this.formatHit(hit, options.query, options.containerName));
        if (options.maxHits && hits.length >= options.maxHits) {
          truncated = true;
          break;
        }
      }
    } catch (error) {
      // Propagate after capturing the hits we already collected.
      const partial: SearchReport = {
        query: maskQuery(options.query),
        containerName: options.containerName,
        fromIso: options.from,
        toIso: options.to,
        totalHits: hits.length,
        hits,
        truncated: true,
        durationMs: Date.now() - start,
      };
      (partial as { error?: string }).error = (error as Error).message;
      return partial;
    }

    return {
      // Redact the user's query in the same way as the excerpts. They know what they
      // searched for; the output is for sharing with reviewers, who don't need the
      // raw term to triage. Drops PCI/PII exposure if the query itself was sensitive.
      query: maskQuery(options.query),
      containerName: options.containerName,
      fromIso: options.from,
      toIso: options.to,
      totalHits: hits.length,
      hits,
      truncated,
      durationMs: Date.now() - start,
    };
  }

  private formatHit(hit: LogHit, query: string, containerName: string | undefined): SearchHitResult {
    const message = hit.message ?? '';
    const matchIndex = this.findQueryIndex(message, query);
    const matchLength = matchIndex < 0 ? 0 : Math.min(query.length, message.length - matchIndex);

    let excerpt: string;
    if (matchIndex >= 0) {
      excerpt = buildRedactedExcerpt(message, matchIndex, matchIndex + matchLength);
    } else {
      // Query matched a structured field rather than the visible message — surface a
      // truncated view of the line with no specific term to redact.
      excerpt = message.slice(0, 200);
    }

    return {
      docId: hit._id,
      index: hit._index,
      timestamp: hit.timestamp,
      container: containerName,
      kibanaUrl: this.client.buildKibanaDeepLink(hit),
      excerpt,
    };
  }

  /**
   * Best-effort: locate where the user's query string occurs in the message. For
   * complex query_string syntax (boolean operators, fields, wildcards) we fall
   * back to scanning the first whitespace-bounded token.
   */
  private findQueryIndex(message: string, query: string): number {
    const trimmed = query.trim();
    // Quoted phrase.
    const quoted = trimmed.match(/^"([^"]+)"$/);
    if (quoted) return message.indexOf(quoted[1]);
    // First token without ES syntax.
    const firstToken = trimmed.split(/[\s()]+/).find((t) => !/^[+\-!]?\w+:/.test(t)) ?? trimmed;
    return message.indexOf(firstToken);
  }
}
