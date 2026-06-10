/**
 * LogReviewAnalyzer integration with a mocked Kibana client.
 *
 * Bank-scale runtime invariants this pins:
 *   - Findings dedup by fingerprint so repeated identical log lines don't fan-out
 *   - PCI redaction: the matched PAN/CVV/etc. is NEVER persisted in the finding
 *   - Severity threshold + heuristic gate operate on log findings exactly as on code
 *   - Deterministic output across runs
 */
import { KibanaClient, LogHit } from '../src/logs/kibanaClient';
import { LogReviewAnalyzer } from '../src/logs/logReviewAnalyzer';

class FakeKibanaClient extends KibanaClient {
  private hits: LogHit[];
  constructor(hits: LogHit[]) {
    super({
      baseUrl: 'http://localhost:5601',
      username: 'u',
      password: 'p',
      transport: 'kibana-proxy',
      index: 'filebeat-*',
    });
    this.hits = hits;
  }
  override async *streamHits(): AsyncIterableIterator<LogHit> {
    for (const hit of this.hits) yield hit;
  }
  override async ping(): Promise<{ ok: boolean; status: number; body: string }> {
    return { ok: true, status: 200, body: '' };
  }
  override buildKibanaDeepLink(hit: LogHit): string {
    return `http://localhost:5601/app/discover#/?_id=${hit._id}`;
  }
}

function hit(overrides: Partial<LogHit>): LogHit {
  return {
    _id: overrides._id ?? 'doc-' + Math.random(),
    _index: overrides._index ?? 'filebeat-2026.05.29',
    source: overrides.source ?? {},
    message: overrides.message ?? '',
    timestamp: overrides.timestamp ?? '2026-05-29T12:00:00Z',
  };
}

describe('LogReviewAnalyzer', () => {
  const baseOptions = {
    containerName: 'payments-svc',
    fromIso: '2026-05-14T00:00:00Z',
    toIso: '2026-05-29T00:00:00Z',
  };

  test('emits findings for PAN / CVV / Emirates ID and never leaks the raw value', async () => {
    const client = new FakeKibanaClient([
      hit({ _id: 'a', message: 'customer payment failed for card 4242424242424242 amount 100' }),
      hit({ _id: 'b', message: 'cvv=123 retry' }),
      // Luhn-valid EID (the rule demotes checksum-failed shapes to MEDIUM).
      hit({ _id: 'c', message: 'customer 784-1990-1234567-6 verified' }),
    ]);

    const report = await new LogReviewAnalyzer(client).analyze(baseOptions);
    const ruleIds = report.findings.map((f) => f.ruleId);

    expect(ruleIds).toContain('LOG-PCI-001');
    expect(ruleIds).toContain('LOG-PCI-002');
    expect(ruleIds).toContain('LOG-PII-001');

    // No finding should ever carry the unmasked PAN / CVV / Emirates ID in any field.
    const allText = JSON.stringify(report);
    expect(allText).not.toContain('4242424242424242');
    expect(allText).not.toContain('784-1990-1234567-6');
  });

  test('dedups identical findings across repeated log lines', async () => {
    const hits = Array.from({ length: 50 }, (_, i) =>
      hit({ _id: 'doc-' + i, message: 'card 4242424242424242 processed' })
    );
    const client = new FakeKibanaClient(hits);

    const report = await new LogReviewAnalyzer(client).analyze(baseOptions);
    const panFindings = report.findings.filter((f) => f.ruleId === 'LOG-PCI-001');
    expect(panFindings.length).toBe(1);
  });

  test('every finding carries logEvidence with a Kibana deep-link', async () => {
    const client = new FakeKibanaClient([
      hit({ _id: 'log-1', message: 'token=Bearer abcdefghijklmnopqrstuvwxyz0123' }),
    ]);
    const report = await new LogReviewAnalyzer(client).analyze(baseOptions);
    const finding = report.findings.find((f) => f.ruleId === 'LOG-SEC-002');
    expect(finding).toBeDefined();
    expect(finding?.logEvidence?.docId).toBe('log-1');
    expect(finding?.logEvidence?.kibanaUrl).toContain('http://localhost:5601');
    expect(finding?.logEvidence?.excerpt.length).toBeGreaterThan(0);
  });

  test('heuristic rules (e.g. LOG-PII-003 email) are gated by default', async () => {
    const client = new FakeKibanaClient([
      hit({ _id: 'email-1', message: 'user alice@bank.ae signed in' }),
    ]);
    const reportDefault = await new LogReviewAnalyzer(client).analyze(baseOptions);
    expect(reportDefault.findings.find((f) => f.ruleId === 'LOG-PII-003')).toBeUndefined();

    const reportHeur = await new LogReviewAnalyzer(client).analyze({ ...baseOptions, includeHeuristics: true });
    expect(reportHeur.findings.find((f) => f.ruleId === 'LOG-PII-003')).toBeDefined();
  });

  test('--disable-rule drops findings for the named rule', async () => {
    const client = new FakeKibanaClient([
      hit({ _id: 'pan-1', message: 'card 4242424242424242 processed' }),
    ]);
    const report = await new LogReviewAnalyzer(client).analyze({
      ...baseOptions,
      disabledRules: ['LOG-PCI-001'],
    });
    expect(report.findings.find((f) => f.ruleId === 'LOG-PCI-001')).toBeUndefined();
  });

  test('clean operational logs produce zero findings', async () => {
    const client = new FakeKibanaClient([
      hit({ _id: 'op-1', message: 'GET /health 200 12ms' }),
      hit({ _id: 'op-2', message: 'request_id=abc-123 completed' }),
      hit({ _id: 'op-3', message: 'queue depth 0' }),
    ]);
    const report = await new LogReviewAnalyzer(client).analyze(baseOptions);
    expect(report.findings.length).toBe(0);
  });

  test('reports the number of hits scanned even when finding count is zero', async () => {
    const hits = Array.from({ length: 7 }, (_, i) => hit({ _id: 'h-' + i, message: 'ok' }));
    const client = new FakeKibanaClient(hits);
    const report = await new LogReviewAnalyzer(client).analyze(baseOptions);
    expect(report.filesAnalyzed).toBe(7);
    expect(report.totalFindings).toBe(0);
  });

  test('output is deterministic — two runs over the same hits produce identical fingerprints', async () => {
    const make = () => new FakeKibanaClient([
      hit({ _id: 'pan-1', message: 'card 4242424242424242' }),
      hit({ _id: 'jwt-1', message: 'token=eyJhbGciOi.eyJzdWIiOi.SflKxw' }),
    ]);
    const r1 = await new LogReviewAnalyzer(make()).analyze(baseOptions);
    const r2 = await new LogReviewAnalyzer(make()).analyze(baseOptions);
    expect(r1.findings.map((f) => f.fingerprint)).toEqual(r2.findings.map((f) => f.fingerprint));
  });
});
