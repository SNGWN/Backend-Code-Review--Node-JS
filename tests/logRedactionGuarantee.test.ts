/**
 * PCI-DSS / UAE PDPL redaction guarantee.
 *
 * For every log rule, run a known-vulnerable line through the entire pipeline
 * (scanner → finding → SARIF) and assert that the raw sensitive value NEVER
 * appears in the resulting JSON. This is a non-negotiable bank-compliance
 * invariant: a security tool that surfaces PAN / CVV / passwords in its OWN
 * output is itself a PCI-DSS reportable event.
 *
 * If this test fails, ship-blocker.
 */
import { KibanaClient, LogHit } from '../src/logs/kibanaClient';
import { LogReviewAnalyzer } from '../src/logs/logReviewAnalyzer';
import { SarifReporter } from '../src/reporter/sarif';

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
  override buildKibanaDeepLink(): string { return ''; }
}

function hit(message: string, id = 'x'): LogHit {
  return { _id: id, _index: 'filebeat-2026', source: { message }, message, timestamp: '2026-05-29T12:00:00Z' };
}

describe('Redaction guarantee: raw sensitive values must NEVER appear in output', () => {
  const SENSITIVE_FIXTURES: Array<{ label: string; raw: string; line: string }> = [
    { label: 'PAN Visa',     raw: '4242424242424242',  line: 'card 4242424242424242 processed' },
    { label: 'PAN Amex',     raw: '378282246310005',   line: 'amex 378282246310005 declined' },
    { label: 'PAN Master',   raw: '5555555555554444',  line: 'mc 5555555555554444 ok' },
    { label: 'CVV',          raw: '777',               line: 'payload {"cvv": "777"}' },
    { label: 'Emirates ID',  raw: '784-1990-1234567-8', line: 'customer 784-1990-1234567-8 verified' },
    { label: 'IBAN GB',      raw: 'GB29NWBK60161331926819', line: 'transfer to GB29NWBK60161331926819 booked' },
    { label: 'IBAN AE',      raw: 'AE070331234567890123456', line: 'IBAN AE070331234567890123456 ok' },
    { label: 'Plain pw',     raw: 'TopSecret!42',      line: 'login password=TopSecret!42 success' },
    { label: 'Env-var pw',   raw: 'Sup3rPriv',         line: 'startup MYSQL_PWD=Sup3rPriv connected' },
    { label: 'Stripe key',   raw: 'sk_live_4eC39HqLyjWDarjtT1zdp7dc', line: 'using sk_live_4eC39HqLyjWDarjtT1zdp7dc to bill' },
    { label: 'AWS access',   raw: 'AKIAIOSFODNN7EXAMPLE', line: 'AKIAIOSFODNN7EXAMPLE detected' },
    { label: 'JWT',          raw: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxw',
                            line: 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxw set' },
    { label: 'DB conn URL',  raw: 'mongodb://admin:Pa55@db:27017', line: 'connect failed: mongodb://admin:Pa55@db:27017/app' },
  ];

  test.each(SENSITIVE_FIXTURES)('finding output never leaks raw value (%s)', async ({ raw, line }) => {
    const client = new FakeKibanaClient([hit(line)]);
    const report = await new LogReviewAnalyzer(client).analyze({
      containerName: 'svc',
      fromIso: '2026-05-14T00:00:00Z',
      toIso: '2026-05-29T00:00:00Z',
      includeHeuristics: true,
    });
    expect(report.findings.length).toBeGreaterThan(0);

    // 1. Raw value must not appear anywhere in the report (excerpt, code, description).
    const reportText = JSON.stringify(report);
    expect(reportText).not.toContain(raw);

    // 2. SARIF output (the artifact AppSec actually ships) must also not contain it.
    const sarif = JSON.stringify(SarifReporter.build(report));
    expect(sarif).not.toContain(raw);
  });

  test('Bulk: a single log line carrying multiple secrets surfaces each but leaks none', async () => {
    const line = 'login user=ali@bank.ae password=Sup3rSekret token=Bearer abcdefghijklmnop1234 card=4111111111111111';
    const client = new FakeKibanaClient([hit(line)]);
    const report = await new LogReviewAnalyzer(client).analyze({
      containerName: 'svc',
      fromIso: '2026-05-14T00:00:00Z',
      toIso: '2026-05-29T00:00:00Z',
      includeHeuristics: true,
    });
    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    expect(ruleIds.size).toBeGreaterThanOrEqual(3);

    const reportText = JSON.stringify(report);
    expect(reportText).not.toContain('Sup3rSekret');
    expect(reportText).not.toContain('4111111111111111');
    expect(reportText).not.toContain('abcdefghijklmnop1234');
  });
});
