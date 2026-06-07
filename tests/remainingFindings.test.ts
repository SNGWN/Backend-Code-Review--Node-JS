import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as ts from 'typescript';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { Finding } from '../src/types';
import { ProjectContext } from '../src/utils/projectContext';
import { KibanaClient, LogHit, FreeTextSearchOptions } from '../src/logs/kibanaClient';
import { SearchAnalyzer } from '../src/logs/searchAnalyzer';
import { Baseline } from '../src/rules/baseline';

/**
 * Regression coverage for the final batch of tracked findings:
 *   - M44   service/repository-layer IDOR (TENTATIVE, surfaced not dropped)
 *   - M15/M43 cross-statement TOCTOU (check and act in sibling statements)
 *   - M10   wildcard `export *` must not shadow a LOCAL function summary
 *   - M32   SearchReport surfaces the ES matched-total, not just the returned count
 *   - baseline ruleId match is case-insensitive
 */

let counter = 0;
function scan(name: string, content: string): Finding[] {
  counter += 1;
  const filePath = path.join(os.tmpdir(), `bcr-remaining-${process.pid}-${counter}-${name}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  const report = new BackendCodeReviewAnalyzer().analyze(filePath, {
    includeHeuristics: true,
    minSeverity: 'LOW',
  });
  return report.findings;
}

describe('M44 — service/repository-layer IDOR', () => {
  test('flags a controller delegating to a service lookup with a bare client id', () => {
    const f = scan('svc-idor.ts', `
      declare const accountService: any;
      export async function getAccount(req: any, res: any) {
        const acct = await accountService.getAccount(req.params.id);
        return res.json(acct);
      }
    `);
    const finding = f.find((x) => /Service\/Repository Layer/i.test(x.title));
    expect(finding).toBeDefined();
    expect(finding?.ruleId).toBe('BCR-AC-005');
    expect(finding?.confidence).toBe('TENTATIVE');
    expect(finding?.verify).toBeTruthy();
  });

  test('does NOT flag when an ownership/tenant id is passed alongside the resource id', () => {
    const f = scan('svc-idor-safe.ts', `
      declare const accountService: any;
      export async function getAccount(req: any, res: any) {
        const acct = await accountService.getAccount(req.params.id, req.user.id);
        return res.json(acct);
      }
    `);
    expect(f.some((x) => /Service\/Repository Layer/i.test(x.title))).toBe(false);
  });

  test('does NOT flag a non-service receiver', () => {
    const f = scan('svc-idor-plain.ts', `
      declare const helpers: any;
      export async function h(req: any) {
        return helpers.getThing(req.params.id);
      }
    `);
    expect(f.some((x) => /Service\/Repository Layer/i.test(x.title))).toBe(false);
  });
});

describe('M15/M43 — cross-statement TOCTOU', () => {
  test('flags a balance read + guard followed by a sibling, non-atomic debit', () => {
    const f = scan('toctou.ts', `
      declare const wallet: any;
      export async function withdraw(req: any) {
        const balance = await wallet.getBalance(req.user.id);
        if (balance < req.body.amount) {
          throw new Error('insufficient');
        }
        await wallet.debit(req.user.id, req.body.amount);
      }
    `);
    const finding = f.find((x) => /TOCTOU.*Across Statements/i.test(x.title));
    expect(finding).toBeDefined();
    expect(finding?.ruleId).toBe('BCR-BL-003');
    expect(finding?.confidence).toBe('TENTATIVE');
  });

  test('does NOT flag when the function takes a lock / mutex', () => {
    const f = scan('toctou-locked.ts', `
      declare const wallet: any;
      declare const mutex: any;
      export async function withdraw(req: any) {
        const release = await mutex.acquire();
        const balance = await wallet.getBalance(req.user.id);
        if (balance < req.body.amount) {
          throw new Error('insufficient');
        }
        await wallet.debit(req.user.id, req.body.amount);
        release();
      }
    `);
    expect(f.some((x) => /TOCTOU.*Across Statements/i.test(x.title))).toBe(false);
  });
});

describe('M10 — wildcard re-export does not shadow a local definition', () => {
  function makeSourceFile(filePath: string, content: string): ts.SourceFile {
    fs.writeFileSync(filePath, content, 'utf-8');
    return ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);
  }

  test('a local tainted-returning function wins over a same-named symbol behind export *', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bcr-m10-'));
    const aFile = path.join(dir, 'a.ts');
    const bFile = path.join(dir, 'b.ts');
    const otherFile = path.join(dir, 'other.ts');

    // b.ts BOTH defines getId locally AND re-exports everything from ./other.
    const bSource = makeSourceFile(
      bFile,
      `export function getId(req: any) { return req.params.id; }\nexport * from './other';\n`
    );
    // ./other also exports a getId — but a SAFE one. The wildcard must not let it shadow b's local.
    const otherSource = makeSourceFile(
      otherFile,
      `export function getId() { return 'static-safe'; }\n`
    );
    fs.writeFileSync(aFile, `import { getId } from './b';\n`, 'utf-8');

    const ctx = new ProjectContext();
    ctx.addFile(bFile, bSource);
    ctx.addFile(otherFile, otherSource);

    const resolved = ctx.resolveImportedSymbol(aFile, { module: './b', exportedName: 'getId' });
    expect(resolved).not.toBeNull();
    // Must resolve to b.ts's LOCAL getId (returns req.params.id → tainted), not other.ts's safe one.
    expect(resolved?.summary?.returnsTaintedFromRequest).toBe(true);
  });
});

describe('M32 — search report surfaces the ES matched-total', () => {
  class TotalReportingClient extends KibanaClient {
    constructor(private hits: LogHit[], private total: { value: number; relation: 'eq' | 'gte' }) {
      super({ baseUrl: 'http://x', username: 'u', password: 'p', transport: 'kibana-proxy', index: '*' });
    }
    override async *searchFreeText(_options: FreeTextSearchOptions): AsyncIterableIterator<LogHit> {
      for (const h of this.hits) yield h;
    }
    override getLastSearchTotal(): { value: number; relation: 'eq' | 'gte' } | null {
      return this.total;
    }
    override buildKibanaDeepLink(): string {
      return 'http://x/link';
    }
  }

  test('matchedTotal reflects all matches while totalHits stays the returned count', async () => {
    const hits: LogHit[] = Array.from({ length: 3 }, (_, i) => ({
      _id: `d${i}`,
      _index: 'filebeat-x',
      source: { message: 'ok' },
      message: 'ok',
      timestamp: '2026-06-07T00:00:00Z',
    }));
    const client = new TotalReportingClient(hits, { value: 4210, relation: 'eq' });
    const report = await new SearchAnalyzer(client).search({
      query: 'q',
      from: '2026-06-01T00:00:00Z',
      to: '2026-06-07T00:00:00Z',
    });
    expect(report.totalHits).toBe(3);
    expect(report.matchedTotal).toBe(4210);
    expect(report.matchedTotalRelation).toBe('eq');
  });
});

describe('captureSearchTotal coerces ES total shapes', () => {
  test('object {value,relation} and bare number both resolve', () => {
    const client = new KibanaClient({
      baseUrl: 'http://x', username: 'u', password: 'p', transport: 'kibana-proxy', index: '*',
    });
    const capture = (client as unknown as { captureSearchTotal: (r: unknown) => void }).captureSearchTotal.bind(client);
    capture({ hits: { total: { value: 99, relation: 'gte' } } });
    expect(client.getLastSearchTotal()).toEqual({ value: 99, relation: 'gte' });
    capture({ hits: { total: 7 } });
    expect(client.getLastSearchTotal()).toEqual({ value: 7, relation: 'eq' });
  });
});

describe('baseline ruleId match is case-insensitive', () => {
  test('a baseline entry with a lower-case ruleId still suppresses an upper-case finding', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bcr-baseline-'));
    const baselinePath = path.join(dir, 'baseline.json');
    // Use a relative file path so normalizePath() matches the baseline entry's relative `file`.
    const sourceFile = 'svc.ts';
    fs.writeFileSync(
      baselinePath,
      JSON.stringify({
        version: 1,
        generatedAt: '',
        entries: [
          { fingerprint: 'deadbeefcafebabe', ruleId: 'bcr-val-001', file: 'svc.ts' },
        ],
      }),
      'utf-8'
    );
    const baseline = new Baseline(baselinePath);
    const finding: Finding = {
      ruleId: 'BCR-VAL-001',
      category: 'VALIDATION',
      severity: 'HIGH',
      title: 'SQL Injection',
      description: 'x',
      file: sourceFile,
      line: 1,
      column: 1,
      code: 'db.query(x)',
      recommendation: 'parameterize',
      fingerprint: 'deadbeefcafebabe',
    };
    expect(baseline.match(finding)).toBeDefined();
  });
});
