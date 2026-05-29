/**
 * KibanaClient HTTP-layer tests against a real in-process HTTP mock server.
 *
 * Verifies the contract that matters in production:
 *   - Auth header is Basic OR ApiKey depending on config
 *   - User-Agent + Connection + kbn-xsrf headers are present
 *   - search_after pagination drives multiple requests until exhausted
 *   - 5xx triggers exponential-backoff retry and eventually succeeds
 *   - 4xx (non-429) is NOT retried
 *   - ECONNRESET is retried (simulated by hanging-up the socket)
 *   - Credentials in URL strings are scrubbed from error messages
 *   - Abort signal terminates the scan cleanly
 *
 * Picks an ephemeral port at startup so concurrent tests don't collide.
 */
import * as http from 'http';
import { AddressInfo } from 'net';
import { KibanaClient, scrubCredentialsFromUrl } from '../src/logs/kibanaClient';

interface ServerHandle {
  server: http.Server;
  port: number;
  requests: Array<{ url: string; method: string; headers: http.IncomingHttpHeaders; body: string }>;
  /** Push canned responses; each request pops one. */
  responses: Array<{ status: number; body: string } | 'reset'>;
}

function startServer(): Promise<ServerHandle> {
  return new Promise((resolve) => {
    const handle: ServerHandle = {
      server: undefined as unknown as http.Server,
      port: 0,
      requests: [],
      responses: [],
    };

    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        handle.requests.push({
          url: req.url ?? '',
          method: req.method ?? '',
          headers: req.headers,
          body: Buffer.concat(chunks).toString('utf-8'),
        });
        const next = handle.responses.shift();
        if (next === 'reset') {
          req.socket.destroy();
          return;
        }
        const response = next ?? { status: 200, body: '{"hits":{"hits":[]}}' };
        res.writeHead(response.status, { 'Content-Type': 'application/json' });
        res.end(response.body);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      handle.server = server;
      handle.port = port;
      resolve(handle);
    });
  });
}

function stopServer(handle: ServerHandle): Promise<void> {
  return new Promise((resolve) => handle.server.close(() => resolve()));
}

describe('KibanaClient HTTP layer', () => {
  let s: ServerHandle;
  beforeEach(async () => { s = await startServer(); });
  afterEach(async () => { await stopServer(s); });

  function makeClient(extra: Partial<ConstructorParameters<typeof KibanaClient>[0]> = {}): KibanaClient {
    return new KibanaClient({
      baseUrl: `http://127.0.0.1:${s.port}`,
      username: 'reader',
      password: 'pa55',
      transport: 'kibana-proxy',
      index: 'filebeat-*',
      maxRetries: 3,
      requestTimeoutMs: 1000,
      ...extra,
    });
  }

  test('sends Basic auth, kbn-xsrf, and User-Agent headers', async () => {
    s.responses.push({ status: 200, body: '{"hits":{"hits":[]}}' });
    const client = makeClient();
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of client.streamHits({ containerName: 'svc', from: 'a', to: 'b' })) { /* consume */ }
    const req = s.requests[0];
    expect(req.headers.authorization).toMatch(/^Basic /);
    // Basic + base64("reader:pa55") == cmVhZGVyOnBhNTU=
    expect(req.headers.authorization).toBe('Basic cmVhZGVyOnBhNTU=');
    expect(req.headers['kbn-xsrf']).toBe('true');
    expect(String(req.headers['user-agent'])).toContain('backend-code-review');
  });

  test('API-key auth replaces Basic when configured', async () => {
    s.responses.push({ status: 200, body: '{"hits":{"hits":[]}}' });
    const client = makeClient({ username: undefined, password: undefined, apiKeyId: 'kid', apiKey: 'kval' });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of client.streamHits({ containerName: 'svc', from: 'a', to: 'b' })) { /* consume */ }
    expect(s.requests[0].headers.authorization).toMatch(/^ApiKey /);
  });

  test('search_after pagination drives multiple requests until exhausted', async () => {
    // Page 1: 2 hits, sort tokens; Page 2: 0 hits → stop.
    s.responses.push({
      status: 200,
      body: JSON.stringify({
        hits: { hits: [
          { _id: '1', _index: 'i', _source: { message: 'one' }, sort: [1, '1'] },
          { _id: '2', _index: 'i', _source: { message: 'two' }, sort: [2, '2'] },
        ]},
      }),
    });
    s.responses.push({ status: 200, body: '{"hits":{"hits":[]}}' });
    // Force pagination by setting pageSize=2 so the first page is "full".
    const client = makeClient();
    const hits: string[] = [];
    for await (const hit of client.streamHits({ containerName: 'svc', from: 'a', to: 'b', pageSize: 2 })) {
      hits.push(hit._id);
    }
    expect(hits).toEqual(['1', '2']);
    expect(s.requests.length).toBeGreaterThanOrEqual(2);
    // The second request body must include `search_after` from the last sort token.
    expect(s.requests[1].body).toContain('search_after');
  });

  test('5xx triggers retry and eventually succeeds', async () => {
    s.responses.push({ status: 503, body: 'service unavailable' });
    s.responses.push({ status: 502, body: 'gateway error' });
    s.responses.push({ status: 200, body: '{"hits":{"hits":[]}}' });
    const client = makeClient({ maxRetries: 3 });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of client.streamHits({ containerName: 'svc', from: 'a', to: 'b' })) { /* consume */ }
    expect(s.requests.length).toBe(3);
  });

  test('4xx (non-429) is NOT retried', async () => {
    s.responses.push({ status: 401, body: '{"error":"unauthorized"}' });
    const client = makeClient({ maxRetries: 3 });
    await expect(async () => {
      for await (const _h of client.streamHits({ containerName: 'svc', from: 'a', to: 'b' })) {
        void _h;
      }
    }).rejects.toThrow(/HTTP 401/);
    expect(s.requests.length).toBe(1);
  }, 5000);

  test('ECONNRESET is retried (server hangs up mid-request)', async () => {
    s.responses.push('reset');
    s.responses.push({ status: 200, body: '{"hits":{"hits":[]}}' });
    const client = makeClient({ maxRetries: 2 });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of client.streamHits({ containerName: 'svc', from: 'a', to: 'b' })) { /* consume */ }
    expect(s.requests.length).toBeGreaterThanOrEqual(2);
  });

  test('abort signal cancels in-flight pagination', async () => {
    s.responses.push({
      status: 200,
      body: JSON.stringify({
        hits: { hits: Array.from({ length: 10 }, (_, i) => ({
          _id: String(i),
          _index: 'i',
          _source: { message: 'x' },
          sort: [i, String(i)],
        }))},
      }),
    });
    const controller = new AbortController();
    const client = makeClient({ abortSignal: controller.signal });
    let seen = 0;
    await expect(async () => {
      for await (const _h of client.streamHits({ containerName: 'svc', from: 'a', to: 'b', pageSize: 10 })) {
        void _h;
        seen += 1;
        if (seen === 3) controller.abort();
      }
    }).rejects.toThrow(/aborted/);
  });

  test('scrubCredentialsFromUrl strips embedded basic-auth', () => {
    expect(scrubCredentialsFromUrl('connect to https://reader:pa55@kibana.bank.ae/api'))
      .toBe('connect to https://[REDACTED]@kibana.bank.ae/api');
    expect(scrubCredentialsFromUrl('mongodb://user:p%40ss@db:27017'))
      .toBe('mongodb://[REDACTED]@db:27017');
    // No-op when no creds present.
    expect(scrubCredentialsFromUrl('plain text'))
      .toBe('plain text');
  });

  test('ping() rejects on auth failure', async () => {
    s.responses.push({ status: 401, body: '{"error":"unauthorized"}' });
    const client = makeClient({ maxRetries: 0 });
    const result = await client.ping();
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
  });
});
