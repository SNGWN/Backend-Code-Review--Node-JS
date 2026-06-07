import { KibanaClient, FreeTextSearchOptions, LogHit } from './kibanaClient';
import { buildRedactedExcerpt, scanLogLine } from './logRules';

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
  /** Number of hits actually returned in `hits[]` (bounded by `maxHits`). */
  totalHits: number;
  /**
   * Total documents that MATCHED the query across the whole window, from ES `track_total_hits`
   * (M32). Distinct from `totalHits`, which is only what was returned. Undefined if the transport
   * didn't report a total. `matchedTotalRelation: 'gte'` means ES capped its count at that value.
   */
  matchedTotal?: number;
  matchedTotalRelation?: 'eq' | 'gte';
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
        ...this.matchedTotalFields(),
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
      ...this.matchedTotalFields(),
      hits,
      truncated,
      durationMs: Date.now() - start,
    };
  }

  /** Pull the ES matched-total (track_total_hits) from the client, if it reported one (M32). */
  private matchedTotalFields(): { matchedTotal?: number; matchedTotalRelation?: 'eq' | 'gte' } {
    const total = this.client.getLastSearchTotal();
    if (!total) return {};
    return { matchedTotal: total.value, matchedTotalRelation: total.relation };
  }

  private formatHit(hit: LogHit, query: string, containerName: string | undefined): SearchHitResult {
    const message = hit.message ?? '';
    // Always run the full rule set over the line so PAN / secrets / PII are masked regardless of
    // what the user's query term was. Without this the tool itself leaks the very data a
    // compliance reviewer must not see into its own report artifact.
    const detected = scanLogLine(message).map((m) => ({ start: m.start, end: m.end }));
    const matchIndex = this.findQueryIndex(message, query);
    const matchLength = matchIndex < 0 ? 0 : Math.min(query.length, message.length - matchIndex);

    // Field boundary: keep the excerpt window inside either the primary message or the appended
    // structured `_source` projection, never straddling both (M30). The anchor decides the field.
    const primaryLength = typeof hit.messageFieldLength === 'number' ? hit.messageFieldLength : message.length;
    const fieldBounds = (anchor: number): { lo: number; hi: number } =>
      anchor >= primaryLength && primaryLength < message.length
        ? { lo: primaryLength + 1, hi: message.length }
        : { lo: 0, hi: primaryLength };
    const label = (anchor: number, text: string): string =>
      anchor >= primaryLength && primaryLength < message.length ? `[_source] ${text}` : text;

    let excerpt: string;
    if (matchIndex >= 0) {
      // Mask the matched span AND every detected secret co-located in the window.
      excerpt = label(matchIndex, buildRedactedExcerpt(message, matchIndex, matchIndex + matchLength, detected, fieldBounds(matchIndex)));
    } else if (detected.length > 0) {
      // Query matched a structured field. Anchor the excerpt on the first detected secret and
      // mask all of them — never echo the raw value back.
      excerpt = label(detected[0].start, buildRedactedExcerpt(message, detected[0].start, detected[0].end, detected, fieldBounds(detected[0].start)));
    } else {
      // No query match and nothing sensitive detected: surface only the primary message head.
      // resolveMessage appends a stringified _source (which may carry nested secrets) after a
      // newline — slicing the first line keeps that raw projection out of the report.
      excerpt = message.split('\n')[0].slice(0, 200);
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
