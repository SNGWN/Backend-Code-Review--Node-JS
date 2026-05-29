/**
 * Free-text search (`--mode search`) tests.
 *
 * Verifies:
 *  - SearchAnalyzer redacts the matched query term in every hit's excerpt
 *  - Hits carry index/_id/timestamp/container/kibanaUrl
 *  - Container scope is optional (entire-cluster search)
 *  - --max-hits is respected (truncated flag set)
 *  - Kibana query body contains `query_string` with the user's query
 */
import { KibanaClient, LogHit, FreeTextSearchOptions } from '../src/logs/kibanaClient';
import { SearchAnalyzer } from '../src/logs/searchAnalyzer';

class FakeSearchClient extends KibanaClient {
  public lastOptions: FreeTextSearchOptions | undefined;
  private hits: LogHit[];
  constructor(hits: LogHit[]) {
    super({
      baseUrl: 'http://kibana.test',
      username: 'u', password: 'p',
      transport: 'kibana-proxy', index: '*',
    });
    this.hits = hits;
  }
  override async *searchFreeText(options: FreeTextSearchOptions): AsyncIterableIterator<LogHit> {
    this.lastOptions = options;
    for (const hit of this.hits) yield hit;
  }
  override async ping(): Promise<{ ok: boolean; status: number; body: string }> {
    return { ok: true, status: 200, body: '' };
  }
  override buildKibanaDeepLink(hit: LogHit): string {
    return `http://kibana.test/app/discover#/?_id=${hit._id}`;
  }
}

function hit(message: string, id: string): LogHit {
  return {
    _id: id,
    _index: 'filebeat-2026.05.29',
    source: { message },
    message,
    timestamp: '2026-05-29T12:00:00Z',
  };
}

describe('SearchAnalyzer', () => {
  test('every hit carries index, doc_id, timestamp, kibanaUrl', async () => {
    const client = new FakeSearchClient([
      hit('user alice@bank.ae logged in', 'doc-1'),
      hit('alice@bank.ae viewed transactions', 'doc-2'),
    ]);
    const report = await new SearchAnalyzer(client).search({
      query: 'alice@bank.ae',
      from: '2026-05-22T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
    });
    expect(report.totalHits).toBe(2);
    expect(report.hits[0].docId).toBe('doc-1');
    expect(report.hits[0].index).toBe('filebeat-2026.05.29');
    expect(report.hits[0].kibanaUrl).toContain('http://kibana.test');
  });

  test('matched query term is redacted in every excerpt', async () => {
    const client = new FakeSearchClient([
      hit('login user=alice@bank.ae status=ok', 'doc-1'),
      hit('alice@bank.ae uploaded statement.pdf', 'doc-2'),
    ]);
    const report = await new SearchAnalyzer(client).search({
      query: 'alice@bank.ae',
      from: '2026-05-22T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
    });
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain('alice@bank.ae');
    // The masked form keeps first 2 + last 2 chars: al*********ae
    expect(report.hits[0].excerpt).toMatch(/al\*+ae/);
  });

  test('container scope is optional — entire-cluster search', async () => {
    const client = new FakeSearchClient([hit('x', 'doc-1')]);
    const report = await new SearchAnalyzer(client).search({
      query: 'x',
      from: '2026-05-22T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
    });
    expect(report.containerName).toBeUndefined();
    expect(report.hits[0].container).toBeUndefined();
    expect(client.lastOptions?.containerName).toBeUndefined();
  });

  test('container scope is honored when provided', async () => {
    const client = new FakeSearchClient([hit('x', 'doc-1')]);
    const report = await new SearchAnalyzer(client).search({
      query: 'x',
      from: '2026-05-22T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
      containerName: 'payments-svc',
    });
    expect(report.containerName).toBe('payments-svc');
    expect(report.hits[0].container).toBe('payments-svc');
    expect(client.lastOptions?.containerName).toBe('payments-svc');
  });

  test('--max-hits is respected with truncated flag', async () => {
    const hits = Array.from({ length: 50 }, (_, i) => hit('match', `doc-${i}`));
    const client = new FakeSearchClient(hits);
    const report = await new SearchAnalyzer(client).search({
      query: 'match',
      from: '2026-05-22T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
      maxHits: 5,
    });
    expect(report.totalHits).toBe(5);
    expect(report.truncated).toBe(true);
  });

  test('zero hits returns empty array, not error', async () => {
    const client = new FakeSearchClient([]);
    const report = await new SearchAnalyzer(client).search({
      query: 'no-match-anywhere',
      from: '2026-05-22T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
    });
    expect(report.totalHits).toBe(0);
    expect(report.hits).toEqual([]);
    expect(report.truncated).toBe(false);
  });
});

describe('KibanaClient.buildFreeTextBody', () => {
  test('query body includes query_string and time-range filter', async () => {
    // Use the real client with a search-handling stub to capture the body.
    let captured: Record<string, unknown> | undefined;
    class CapturingClient extends KibanaClient {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      private async testCapture(body: any): Promise<void> { captured = body; }
      override async *searchFreeText(options: FreeTextSearchOptions): AsyncIterableIterator<LogHit> {
        // Re-use the real body builder via type assertion.
        const body = (this as unknown as { buildFreeTextBody: (o: FreeTextSearchOptions, n: number) => Record<string, unknown> })
          .buildFreeTextBody(options, options.pageSize ?? 100);
        await this.testCapture(body);
        return;
        yield {} as LogHit; // unreachable; satisfies generator typing
      }
    }
    const client = new CapturingClient({
      baseUrl: 'http://x', username: 'u', password: 'p',
      transport: 'kibana-proxy', index: '*',
    });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of client.searchFreeText({
      query: 'alice OR bob',
      from: '2026-05-01T00:00:00Z',
      to: '2026-05-29T00:00:00Z',
      containerName: 'payments',
    })) { /* consume */ }
    expect(captured).toBeDefined();
    const bool = (captured as { query: { bool: { must: unknown[]; filter: unknown[] } } }).query.bool;
    const queryString = (bool.must[0] as { query_string: { query: string } }).query_string;
    expect(queryString.query).toBe('alice OR bob');
    expect(bool.filter.length).toBeGreaterThanOrEqual(2); // time range + container term
  });
});
