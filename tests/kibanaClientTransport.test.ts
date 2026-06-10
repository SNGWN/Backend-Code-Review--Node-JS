import * as http from 'http';
import { AddressInfo } from 'net';
import { KibanaClient, shouldForwardAuth } from '../src/logs/kibanaClient';

/**
 * Transport behavior of the KibanaClient against real local HTTP servers:
 * redirect following (same-origin auth forwarding, cross-origin stripping, loop guard)
 * and forward-proxy support (absolute-URI for http targets, CONNECT for https).
 */

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  });
}

const close = (server: http.Server): Promise<void> =>
  new Promise((resolve) => server.close(() => resolve()));

function makeClient(baseUrl: string, extra: Partial<ConstructorParameters<typeof KibanaClient>[0]> = {}): KibanaClient {
  return new KibanaClient({
    baseUrl,
    username: 'u',
    password: 'p',
    transport: 'direct',
    index: 'filebeat-*',
    ...extra,
  });
}

describe('KibanaClient redirects', () => {
  test('follows a same-origin redirect and forwards Authorization', async () => {
    const seen: Array<{ url: string; auth?: string }> = [];
    const server = http.createServer((req, res) => {
      seen.push({ url: req.url ?? '', auth: req.headers.authorization });
      if (req.url === '/_cluster/health') {
        res.writeHead(302, { Location: '/moved/health' });
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'green' }));
    });
    const port = await listen(server);
    try {
      const client = makeClient(`http://127.0.0.1:${port}`);
      const ping = await client.ping();
      expect(ping.ok).toBe(true);
      expect(seen).toHaveLength(2);
      expect(seen[1].url).toBe('/moved/health');
      expect(seen[1].auth).toMatch(/^Basic /);
    } finally {
      await close(server);
    }
  });

  test('strips Authorization on a cross-origin redirect', async () => {
    const other = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ auth: req.headers.authorization ?? null }));
    });
    const otherPort = await listen(other);

    const origin = http.createServer((_req, res) => {
      // Different port == different origin.
      res.writeHead(302, { Location: `http://127.0.0.1:${otherPort}/elsewhere` });
      res.end();
    });
    const originPort = await listen(origin);

    try {
      const client = makeClient(`http://127.0.0.1:${originPort}`);
      const ping = await client.ping();
      expect(ping.ok).toBe(true);
      expect(JSON.parse(ping.body).auth).toBeNull();
    } finally {
      await close(origin);
      await close(other);
    }
  });

  test('fails with a redirect-loop error instead of spinning forever', async () => {
    const server = http.createServer((req, res) => {
      res.writeHead(302, { Location: req.url === '/a' ? '/b' : '/a' });
      res.end();
    });
    const port = await listen(server);
    try {
      const client = makeClient(`http://127.0.0.1:${port}`, { maxRetries: 0 });
      await expect(client.ping()).rejects.toThrow(/redirect/i);
    } finally {
      await close(server);
    }
  });
});

describe('shouldForwardAuth (redirect credential policy)', () => {
  test('forwards on the same origin', () => {
    expect(shouldForwardAuth('https://kibana.bank.ae:5601', 'https://kibana.bank.ae:5601/api/status')).toBe(true);
  });

  test('forwards on a same-host http→https upgrade (LB/SSO gateway pattern)', () => {
    expect(shouldForwardAuth('http://kibana.bank.ae', 'https://kibana.bank.ae/api/status')).toBe(true);
    expect(shouldForwardAuth('http://kibana.bank.ae:5601', 'https://kibana.bank.ae:443/api/status')).toBe(true);
  });

  test('never forwards on a TLS downgrade', () => {
    expect(shouldForwardAuth('https://kibana.bank.ae', 'http://kibana.bank.ae/api/status')).toBe(false);
  });

  test('never forwards to a different host', () => {
    expect(shouldForwardAuth('https://kibana.bank.ae', 'https://evil.example.com/api/status')).toBe(false);
    expect(shouldForwardAuth('http://kibana.bank.ae', 'https://evil.example.com/api/status')).toBe(false);
  });
});

describe('KibanaClient forward proxy', () => {
  test('routes http-target requests through the proxy as absolute-URI', async () => {
    const upstream = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'green' }));
    });
    const upstreamPort = await listen(upstream);

    const proxiedUrls: string[] = [];
    const proxy = http.createServer((req, res) => {
      proxiedUrls.push(req.url ?? '');
      // Forward to the upstream based on the absolute-URI the client sent.
      const target = new URL(req.url as string);
      const fwd = http.request(
        { hostname: target.hostname, port: target.port, path: target.pathname, method: req.method, headers: req.headers },
        (upRes) => {
          res.writeHead(upRes.statusCode ?? 502, upRes.headers);
          upRes.pipe(res);
        }
      );
      req.pipe(fwd);
    });
    const proxyPort = await listen(proxy);

    try {
      const client = makeClient(`http://127.0.0.1:${upstreamPort}`, {
        proxyUrl: `http://127.0.0.1:${proxyPort}`,
      });
      const ping = await client.ping();
      expect(ping.ok).toBe(true);
      expect(proxiedUrls).toHaveLength(1);
      expect(proxiedUrls[0]).toBe(`http://127.0.0.1:${upstreamPort}/_cluster/health`);
    } finally {
      await close(proxy);
      await close(upstream);
    }
  });

  test('a refused proxy fails with a scrubbed, proxy-specific error', async () => {
    const upstream = http.createServer((_req, res) => { res.writeHead(200); res.end('{}'); });
    const upstreamPort = await listen(upstream);
    try {
      const client = makeClient(`https://127.0.0.1:${upstreamPort}`, {
        // Port 9 (discard) — nothing listens; CONNECT must fail fast.
        proxyUrl: 'http://secretuser:secretpass@127.0.0.1:9',
        maxRetries: 0,
      });
      await expect(client.ping()).rejects.toThrow(/Proxy/i);
      await expect(client.ping()).rejects.not.toThrow(/secretpass/);
    } finally {
      await close(upstream);
    }
  });

  test('rejects an invalid proxy URL at construction', () => {
    expect(() => makeClient('http://127.0.0.1:9200', { proxyUrl: 'not a url' })).toThrow(/proxy/i);
    expect(() => makeClient('http://127.0.0.1:9200', { proxyUrl: 'ftp://proxy:21' })).toThrow(/http or https/);
  });

  test('does not retain raw proxy credentials on the stored URL object', () => {
    const client = makeClient('http://127.0.0.1:9200', {
      proxyUrl: 'http://secretuser:secretpass@127.0.0.1:8080',
    });
    // The credential must survive only inside the prebuilt Proxy-Authorization header,
    // never on the long-lived URL object (heap snapshots / debug dumps).
    const stored = (client as unknown as { proxy: URL }).proxy;
    expect(stored.username).toBe('');
    expect(stored.password).toBe('');
    expect(stored.href).not.toContain('secretpass');
  });
});
