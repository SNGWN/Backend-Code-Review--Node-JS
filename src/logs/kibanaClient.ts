import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';

/**
 * Scrubs Basic-auth credentials from URLs we put into error messages.
 * `https://u:p@host/path` → `https://[REDACTED]@host/path`. Critical so our own
 * exception stack traces don't leak the Kibana password into ops dashboards.
 */
export function scrubCredentialsFromUrl(value: string): string {
  return value.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi, '$1[REDACTED]@');
}

/**
 * Minimal Elasticsearch / Kibana search client.
 *
 * Two transport modes:
 *   - direct ES (`/<index>/_search`) — fastest, but blocked in many bank networks
 *   - Kibana console-proxy (`/api/console/proxy?path=/<index>/_search&method=POST`)
 *     — the more common gateway in restricted environments. Requires `kbn-xsrf` header.
 *
 * Auth: HTTP Basic with username + password. The client NEVER logs the password.
 * The constructor does not store credentials in plaintext properties — they're closed
 * over inside `request()`.
 *
 * Pagination: search_after on `@timestamp` + `_id` tiebreaker. Reliable for time-window
 * queries; doesn't suffer from the deep-scroll limits that `from`/`size` hit at 10k.
 */

export type KibanaTransport = 'direct' | 'kibana-proxy';

export interface KibanaClientConfig {
  /** Base URL of Kibana (e.g. https://kibana.bank.ae:5601) or ES (https://es:9200). */
  baseUrl: string;
  /**
   * Auth: either Basic (username + password) OR ES API key (apiKeyId + apiKey).
   * Banks running newer ES clusters typically prefer API keys for service-to-service.
   */
  username?: string;
  password?: string;
  apiKeyId?: string;
  apiKey?: string;
  /**
   * SSO bearer token (Okta, PingFederate, Cognito, OIDC). Mutually exclusive with
   * Basic + ApiKey auth.
   */
  bearerToken?: string;
  transport: KibanaTransport;
  /** Index pattern to search (e.g. `filebeat-*`, `logstash-*`). */
  index: string;
  /**
   * Field name carrying the container identifier. Defaults to `kubernetes.container.name`
   * (Filebeat with k8s metadata). Common alternates: `container.name` (Docker autodiscover),
   * `docker.container.name` (older Filebeat).
   */
  containerField?: string;
  /**
   * Whether to validate the server TLS cert. Defaults to true. Some bank Kibanas use
   * private CAs — the user can opt out with `--insecure` but we warn loudly.
   */
  rejectUnauthorized?: boolean;
  /** Optional override of the timestamp field. */
  timestampField?: string;
  /**
   * Maximum number of automatic retries on transient HTTP errors (5xx, ECONNRESET).
   * Default 3 with exponential backoff.
   */
  maxRetries?: number;
  /**
   * Per-request timeout in ms. Default 30s — bank clusters under load can take this long.
   */
  requestTimeoutMs?: number;
  /**
   * Progress callback invoked every N hits with the running total. Defaults to no-op.
   */
  onProgress?: (hitsScanned: number) => void;
  /**
   * AbortSignal that can be used to interrupt long-running scans (e.g. for SIGINT).
   */
  abortSignal?: AbortSignal;
}

export interface LogHit {
  _id: string;
  _index: string;
  source: Record<string, unknown>;
  /** Best-effort extraction of the human log line — see resolveMessage. */
  message: string;
  /**
   * Length of the PRIMARY message portion of `message`. `resolveMessage` appends a
   * stringified `_source` projection (so rules can scan nested fields) after a newline;
   * everything at offset `< messageFieldLength` is the human-facing Kibana `message` field,
   * everything after the boundary is the structured projection. Excerpt builders use this to
   * keep a finding's window — and its reported column — inside a single coherent field rather
   * than letting it straddle the synthetic boundary (M30). Optional so hand-built hits (tests,
   * non-client callers) default to treating the whole string as the primary message.
   */
  messageFieldLength?: number;
  /** ISO timestamp. */
  timestamp: string;
}

/** Parsed message: the primary human line plus a bounded stringified `_source` projection. */
export interface ResolvedMessage {
  message: string;
  /** Offset where the structured `_source` projection begins (== primary length), if appended. */
  primaryLength: number;
}

export interface SearchOptions {
  containerName: string;
  /** ISO range start. */
  from: string;
  /** ISO range end (exclusive). */
  to: string;
  /** Page size. ES default is 10. We use 500 for throughput; bank clusters typically allow it. */
  pageSize?: number;
  /** Maximum hits to fetch. Hard ceiling to protect against runaway scans. */
  maxHits?: number;
}

/**
 * Free-text search options. Used by `--mode search` for investigative lookups across
 * the entire cluster OR a specific container.
 */
export interface FreeTextSearchOptions {
  /** The user-supplied query string. Sent to ES as a `query_string`. */
  query: string;
  /** ISO range start. */
  from: string;
  /** ISO range end (exclusive). */
  to: string;
  /** Optional container scope. When omitted, searches all containers visible to the user. */
  containerName?: string;
  pageSize?: number;
  maxHits?: number;
}

const DEFAULT_TIMESTAMP_FIELD = '@timestamp';
const DEFAULT_CONTAINER_FIELD = 'kubernetes.container.name';
const DEFAULT_PAGE_SIZE = 500;
const DEFAULT_MAX_HITS = 50_000;

export class KibanaClient {
  private readonly baseUrl: string;
  private readonly transport: KibanaTransport;
  private readonly index: string;
  private readonly containerField: string;
  private readonly timestampField: string;
  private readonly rejectUnauthorized: boolean;
  private readonly authHeader: string;
  private readonly maxRetries: number;
  private readonly requestTimeoutMs: number;
  private readonly onProgress: ((n: number) => void) | undefined;
  private readonly abortSignal: AbortSignal | undefined;
  /** Reuse HTTP sockets across requests — pagination ships dozens of calls. */
  private readonly httpAgent: http.Agent;
  private readonly httpsAgent: https.Agent;
  /**
   * Total matched-document count from the most recent `searchFreeText` run, captured via
   * `track_total_hits`. Reflects how many docs MATCHED, not how many were returned (which the
   * page-size / maxHits cap bounds). `relation: 'gte'` means ES stopped counting at its cap.
   */
  private lastSearchTotal: { value: number; relation: 'eq' | 'gte' } | null = null;

  constructor(config: KibanaClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.transport = config.transport;
    this.index = config.index;
    this.containerField = config.containerField ?? DEFAULT_CONTAINER_FIELD;
    this.timestampField = config.timestampField ?? DEFAULT_TIMESTAMP_FIELD;
    this.rejectUnauthorized = config.rejectUnauthorized ?? true;
    this.maxRetries = config.maxRetries ?? 3;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 30_000;
    this.onProgress = config.onProgress;
    this.abortSignal = config.abortSignal;

    // Build the auth header once; never store password as a property after this point.
    if (config.bearerToken) {
      this.authHeader = `Bearer ${config.bearerToken}`;
    } else if (config.apiKeyId && config.apiKey) {
      const encoded = Buffer.from(`${config.apiKeyId}:${config.apiKey}`, 'utf-8').toString('base64');
      this.authHeader = `ApiKey ${encoded}`;
    } else if (config.username && config.password) {
      const credential = `${config.username}:${config.password}`;
      this.authHeader = `Basic ${Buffer.from(credential, 'utf-8').toString('base64')}`;
    } else {
      throw new Error('KibanaClient requires (username + password) OR (apiKeyId + apiKey) OR bearerToken');
    }

    this.httpAgent = new http.Agent({ keepAlive: true, maxSockets: 4 });
    this.httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 4, rejectUnauthorized: this.rejectUnauthorized });
  }

  /**
   * Stream search hits across a time window. Yields hits as ES returns them.
   * The caller controls memory by consuming the iterator.
   */
  async *streamHits(options: SearchOptions): AsyncIterableIterator<LogHit> {
    const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
    const maxHits = options.maxHits ?? DEFAULT_MAX_HITS;
    let yielded = 0;
    let searchAfter: unknown[] | undefined;
    // Dedup across page boundaries — timestamp-only sort can re-return a doc that shared the
    // boundary timestamp with the previous page's last hit.
    const seenIds = new Set<string>();

    while (yielded < maxHits) {
      if (this.abortSignal?.aborted) {
        throw new Error('Log scan aborted by caller');
      }
      const body = this.buildSearchBody(options, pageSize, searchAfter);
      const response = await this.search(body);

      const hits = (response.hits?.hits ?? []) as Array<{
        _id: string;
        _index: string;
        _source: Record<string, unknown>;
        sort?: unknown[];
      }>;
      if (hits.length === 0) return;

      for (const hit of hits) {
        if (yielded >= maxHits) return;
        if (this.abortSignal?.aborted) {
          throw new Error('Log scan aborted by caller');
        }
        if (hit._id && seenIds.has(hit._id)) continue;
        if (hit._id) seenIds.add(hit._id);
        const source = hit._source ?? {};
        const resolved = this.resolveMessage(source);
        yield {
          _id: hit._id,
          _index: hit._index,
          source,
          message: resolved.message,
          messageFieldLength: resolved.primaryLength,
          timestamp: this.resolveTimestamp(source),
        };
        yielded += 1;
        if (this.onProgress && yielded % 500 === 0) {
          try {
            this.onProgress(yielded);
          } catch {
            /* progress callback failures don't abort the scan */
          }
        }
      }

      const last = hits[hits.length - 1];
      if (!last.sort) return;
      searchAfter = last.sort;
      if (hits.length < pageSize) return;
    }
  }

  /**
   * Free-text search across the configured index pattern. Streams hits like
   * `streamHits()` but with a user-supplied `query_string` and optional container scope.
   * When `containerName` is omitted, searches the entire index (every container the
   * user has read access to).
   */
  async *searchFreeText(options: FreeTextSearchOptions): AsyncIterableIterator<LogHit> {
    const pageSize = options.pageSize ?? 100;
    const maxHits = options.maxHits ?? 1_000;
    let yielded = 0;
    let searchAfter: unknown[] | undefined;
    const seenIds = new Set<string>();
    // Reset the matched-total so a prior run's value can't leak into this one.
    this.lastSearchTotal = null;

    while (yielded < maxHits) {
      if (this.abortSignal?.aborted) {
        throw new Error('Search aborted by caller');
      }
      const body = this.buildFreeTextBody(options, pageSize, searchAfter);
      const response = await this.search(body);
      this.captureSearchTotal(response);

      const hits = (response.hits?.hits ?? []) as Array<{
        _id: string;
        _index: string;
        _source: Record<string, unknown>;
        sort?: unknown[];
      }>;
      if (hits.length === 0) return;

      for (const hit of hits) {
        if (yielded >= maxHits) return;
        if (this.abortSignal?.aborted) {
          throw new Error('Search aborted by caller');
        }
        if (hit._id && seenIds.has(hit._id)) continue;
        if (hit._id) seenIds.add(hit._id);
        const source = hit._source ?? {};
        const resolved = this.resolveMessage(source);
        yield {
          _id: hit._id,
          _index: hit._index,
          source,
          message: resolved.message,
          messageFieldLength: resolved.primaryLength,
          timestamp: this.resolveTimestamp(source),
        };
        yielded += 1;
        if (this.onProgress && yielded % 100 === 0) {
          try { this.onProgress(yielded); } catch { /* swallow */ }
        }
      }

      const last = hits[hits.length - 1];
      if (!last.sort) return;
      searchAfter = last.sort;
      if (hits.length < pageSize) return;
    }
  }

  /**
   * Single-shot health check. Useful for the CLI to fail fast when credentials are wrong
   * before kicking off a 15-day scan.
   */
  async ping(): Promise<{ ok: boolean; status: number; body: string }> {
    const url = this.transport === 'kibana-proxy'
      ? `${this.baseUrl}/api/status`
      : `${this.baseUrl}/_cluster/health`;
    const { status, body } = await this.request('GET', url);
    return { ok: status >= 200 && status < 300, status, body };
  }

  private buildSearchBody(options: SearchOptions, pageSize: number, searchAfter?: unknown[]): Record<string, unknown> {
    const body: Record<string, unknown> = {
      size: pageSize,
      // Sort on the timestamp only. The previous `{ _id: 'asc' }` tiebreaker requires fielddata
      // on `_id`, which Elasticsearch disables by default since 7.6 — sorting on it returns a
      // hard 400 (illegal_argument_exception) and aborts the whole scan. Duplicates that can
      // appear at a page boundary when several docs share a timestamp are removed client-side
      // by the `_id` dedup set in streamHits/searchFreeText.
      sort: [
        { [this.timestampField]: { order: 'asc' } },
      ],
      query: {
        bool: {
          filter: [
            {
              range: {
                [this.timestampField]: {
                  gte: options.from,
                  lt: options.to,
                },
              },
            },
            // Support comma-separated container lists for multi-service compliance scans.
            ...this.buildContainerFilters(options.containerName),
          ],
        },
      },
      // Only pull fields we actually inspect — reduces transfer.
      _source: ['message', 'log', 'msg', 'event.original', this.timestampField, this.containerField],
    };
    if (searchAfter) body.search_after = searchAfter;
    return body;
  }

  private buildFreeTextBody(options: FreeTextSearchOptions, pageSize: number, searchAfter?: unknown[]): Record<string, unknown> {
    const filter: unknown[] = [
      {
        range: {
          [this.timestampField]: { gte: options.from, lt: options.to },
        },
      },
    ];
    if (options.containerName) {
      const containers = options.containerName.split(',').map((s) => s.trim()).filter(Boolean);
      if (containers.length > 0) filter.push(this.containerMatch(containers));
    }

    const body: Record<string, unknown> = {
      size: pageSize,
      // Count ALL matching docs, not just the page returned, so the report can show
      // "showing N of M matched" instead of mislabeling the returned-count as the total (M32).
      // `true` makes ES count exactly; without it ES stops at 10 000 and reports `gte`.
      track_total_hits: true,
      // Timestamp-only sort — see buildSearchBody for why the `_id` tiebreaker was removed.
      sort: [
        { [this.timestampField]: { order: 'desc' } },
      ],
      query: {
        bool: {
          must: [
            {
              query_string: {
                query: options.query,
                // Restrict to the known message fields. Querying `*` fans the user's query
                // across every field in every index (cluster-wide blast radius + DoS surface);
                // `allow_leading_wildcard:false` blocks the `*term` form that forces full-index
                // scans, and the determinized-states cap bounds pathological regex/wildcards.
                fields: ['message', 'msg', 'log.message', 'event.original'],
                default_operator: 'AND',
                lenient: true,
                allow_leading_wildcard: false,
                max_determinized_states: 10000,
              },
            },
          ],
          filter,
        },
      },
      _source: ['message', 'log', 'msg', 'event.original', this.timestampField, this.containerField],
    };
    if (searchAfter) body.search_after = searchAfter;
    return body;
  }

  private buildContainerFilters(containerName: string): unknown[] {
    const containers = containerName.split(',').map((s) => s.trim()).filter(Boolean);
    if (containers.length === 0) return [];
    return [this.containerMatch(containers)];
  }

  /**
   * Match the container on BOTH the analyzed field and its `.keyword` multifield. Clusters differ
   * on whether the container field is keyword-typed (ECS) or text+keyword — hardcoding `.keyword`
   * silently returns zero hits on keyword-only mappings.
   */
  private containerMatch(containers: string[]): unknown {
    const field = this.containerField;
    const make = (f: string): unknown =>
      containers.length === 1 ? { term: { [f]: containers[0] } } : { terms: { [f]: containers } };
    return { bool: { should: [make(`${field}.keyword`), make(field)], minimum_should_match: 1 } };
  }

  /**
   * Matched-document total from the most recent `searchFreeText` run (via `track_total_hits`),
   * or null if no free-text search has run. `relation: 'gte'` means ES capped the count.
   */
  getLastSearchTotal(): { value: number; relation: 'eq' | 'gte' } | null {
    return this.lastSearchTotal;
  }

  /** Record the ES `hits.total` from a response. Keeps the largest value seen across pages. */
  private captureSearchTotal(response: { hits?: { total?: unknown } }): void {
    const total = response.hits?.total;
    if (typeof total === 'number' && Number.isFinite(total)) {
      this.lastSearchTotal = { value: total, relation: 'eq' };
      return;
    }
    if (total && typeof total === 'object') {
      const value = (total as { value?: unknown }).value;
      const relation = (total as { relation?: unknown }).relation;
      if (typeof value === 'number' && Number.isFinite(value)) {
        this.lastSearchTotal = {
          value,
          relation: relation === 'gte' ? 'gte' : 'eq',
        };
      }
    }
  }

  private async search(body: Record<string, unknown>): Promise<{ hits?: { hits?: unknown[]; total?: unknown } }> {
    const path = `/${encodeURIComponent(this.index)}/_search`;
    const url = this.transport === 'kibana-proxy'
      ? `${this.baseUrl}/api/console/proxy?path=${encodeURIComponent(path)}&method=POST`
      : `${this.baseUrl}${path}`;

    const { status, body: respBody } = await this.requestWithRetry('POST', url, body);
    if (status < 200 || status >= 300) {
      // Surface the most common operational error shapes specifically.
      if (status === 404 && /index_not_found_exception/.test(respBody)) {
        throw new Error(`Index pattern '${this.index}' not found in Elasticsearch. Use --log-index or verify in Kibana index management.`);
      }
      if (status === 401 || status === 403) {
        throw new Error(`Elasticsearch auth ${status === 401 ? 'failed' : 'forbidden'} (HTTP ${status}). Verify credentials and index read permissions.`);
      }
      throw new Error(`Elasticsearch search failed: HTTP ${status} ${scrubCredentialsFromUrl(truncate(respBody, 500))}`);
    }
    try {
      return JSON.parse(respBody);
    } catch (error) {
      // A 200 OK with non-JSON body is usually an upstream LB or proxy serving an
      // HTML error page in front of Kibana. Surface the body prefix so the operator
      // can diagnose which hop returned it.
      const preview = scrubCredentialsFromUrl(truncate(respBody.trim(), 200));
      throw new Error(`Elasticsearch returned HTTP 200 with non-JSON body (likely an upstream proxy/LB error page). First 200 bytes: ${preview}`);
    }
  }

  /**
   * HTTP request with exponential backoff retry on transient failures.
   * Retries on: HTTP 5xx, 429, network ECONNRESET / ETIMEDOUT. Does NOT retry on 4xx
   * (other than 429) — those are client errors and retry just wastes the rate-limit.
   */
  private async requestWithRetry(method: string, urlString: string, body?: unknown): Promise<{ status: number; body: string }> {
    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (this.abortSignal?.aborted) {
        throw new Error('Aborted before request');
      }
      try {
        const result = await this.request(method, urlString, body);
        // Retry on 5xx and 429 only.
        if (result.status >= 500 || result.status === 429) {
          lastError = new Error(`HTTP ${result.status}: ${truncate(result.body, 200)}`);
          if (attempt < this.maxRetries) {
            await sleep(backoffMs(attempt));
            continue;
          }
        }
        return result;
      } catch (error) {
        const err = error as NodeJS.ErrnoException;
        const isTransient =
          err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' || err.code === 'EAI_AGAIN' ||
          err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND';
        if (!isTransient || attempt >= this.maxRetries) {
          // Scrub URL credentials from the error message before propagating.
          err.message = scrubCredentialsFromUrl(err.message ?? String(err));
          throw err;
        }
        lastError = err;
        await sleep(backoffMs(attempt));
      }
    }
    throw lastError ?? new Error('Request failed after retries');
  }

  private request(method: string, urlString: string, body?: unknown): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      const url = new URL(urlString);
      const lib = url.protocol === 'https:' ? https : http;
      const payload = body !== undefined ? Buffer.from(JSON.stringify(body), 'utf-8') : undefined;

      const headers: Record<string, string> = {
        Accept: 'application/json',
        Authorization: this.authHeader,
        'User-Agent': 'backend-code-review/1.0 (log-review)',
        Connection: 'keep-alive',
      };
      if (payload) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = String(payload.length);
      }
      // Kibana proxy requires CSRF header.
      if (this.transport === 'kibana-proxy') {
        headers['kbn-xsrf'] = 'true';
      }

      const requestOptions: http.RequestOptions = {
        method,
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        headers,
        timeout: this.requestTimeoutMs,
        agent: lib === https ? this.httpsAgent : this.httpAgent,
      };

      const request = lib.request(requestOptions, (response) => {
        const chunks: Buffer[] = [];
        let received = 0;
        // Cap the buffered response. A compromised/hostile upstream (or an LB serving a huge error
        // page) could otherwise stream unbounded data into memory and then JSON.parse it.
        const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
        let aborted = false;
        response.on('data', (chunk: Buffer) => {
          if (aborted) return;
          received += chunk.length;
          if (received > MAX_RESPONSE_BYTES) {
            aborted = true;
            request.destroy(new Error(`Response exceeded ${MAX_RESPONSE_BYTES} byte cap`));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (aborted) return;
          const responseBody = Buffer.concat(chunks).toString('utf-8');
          resolve({ status: response.statusCode ?? 0, body: responseBody });
        });
      });
      request.on('timeout', () => {
        request.destroy(new Error(`Request timed out after ${this.requestTimeoutMs}ms`));
      });
      request.on('error', (error) => {
        reject(error);
      });
      if (payload) request.write(payload);
      request.end();
    });
  }

  /**
   * ES indexers don't agree on the message field name. We probe the most common ones
   * AND always concatenate a stringified _source projection — many banks ship
   * structured JSON logs where credentials/PAN live in NESTED fields
   * (e.g. `req.body.password`, `headers.authorization`). Scanning only the top-level
   * `message` would miss those entirely.
   *
   * Output: `<primary message>\n<stringified _source>` so the rule engine sees both, PLUS the
   * boundary offset (`primaryLength`) so callers can keep each finding's excerpt and reported
   * column inside ONE coherent field. A match in the primary region maps directly to Kibana's
   * `message` field; a match in the structured region is labeled as `_source` rather than reported
   * at a column that doesn't exist in the human message (M30).
   */
  private resolveMessage(source: Record<string, unknown>): ResolvedMessage {
    const candidates: unknown[] = [
      source.message,
      source.msg,
      (source.event as Record<string, unknown> | undefined)?.original,
      (source.log as Record<string, unknown> | undefined)?.message,
    ];
    let primary = '';
    for (const value of candidates) {
      if (typeof value === 'string' && value.length > 0) { primary = value; break; }
    }
    let structured = '';
    try {
      structured = JSON.stringify(source);
    } catch {
      structured = '';
    }
    // Bound the structured projection. Some indexers ship multi-megabyte _source docs; appending
    // the whole thing per hit blows up memory across a 50k-hit scan and feeds an unbounded string
    // to every per-line regex. 16KB is far more than any real credential/PAN needs.
    const MAX_STRUCTURED = 16 * 1024;
    if (structured.length > MAX_STRUCTURED) structured = structured.slice(0, MAX_STRUCTURED);
    if (primary && structured) {
      return { message: `${primary}\n${structured}`, primaryLength: primary.length };
    }
    const message = primary || structured;
    // No appended structured part (or no primary) — the whole string is one field.
    return { message, primaryLength: message.length };
  }

  private resolveTimestamp(source: Record<string, unknown>): string {
    const value = source[this.timestampField];
    if (typeof value === 'string') return value;
    // Filebeat/ECS sometimes ship `@timestamp` as epoch_millis (a number). Coerce so the field
    // isn't silently dropped (which left deep-links and report timestamps blank).
    if (typeof value === 'number' && Number.isFinite(value)) {
      try {
        return new Date(value).toISOString();
      } catch {
        return '';
      }
    }
    return '';
  }

  /**
   * Builds a Kibana Discover deep-link to a specific document by _id, so reviewers can
   * jump directly from a finding to the source log in Kibana.
   */
  buildKibanaDeepLink(hit: LogHit): string {
    // Kibana >= 7 uses `app/discover` with rison-encoded state. Building a perfect link
    // requires a saved search id; we ship a best-effort link to a doc lookup.
    // `_id` and timestamp originate from Elasticsearch documents (attacker-influenceable for any
    // service that writes its own logs) — URL-encode them so a crafted `_id` cannot break out of
    // the rison/query context and inject extra URL state.
    const safeId = encodeURIComponent(hit._id);
    const safeTs = encodeURIComponent(hit.timestamp);
    const path = `/app/discover#/?_g=(time:(from:'${safeTs}',to:now))&_a=(index:'${this.index}',query:(language:kuery,query:'_id:"${safeId}"'))`;
    return `${this.baseUrl}${path}`;
  }
}

function truncate(text: string, length: number): string {
  return text.length <= length ? text : text.slice(0, length - 1) + '…';
}

/** Sleep for `ms` milliseconds. Used between retry attempts. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Exponential backoff with jitter. Sequence: 500ms, 1s, 2s, 4s … capped at 30s.
 * Adds up to 30% jitter to avoid synchronized retries when multiple scanners hit ES.
 */
function backoffMs(attempt: number): number {
  const base = Math.min(30_000, 500 * Math.pow(2, attempt));
  const jitter = Math.floor(Math.random() * base * 0.3);
  return base + jitter;
}
