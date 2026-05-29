/**
 * Cross-file workflow regression tests.
 *
 * These fixtures encode the cross-file vulnerability shapes that single-file
 * scanning misses. The ProjectContext + two-pass analyzer must catch them.
 *
 * Fixtures live in `tests/fixtures/cross-file/`:
 *   F1 — exported source helper returns user-controlled data; sink in another file
 *   F3 — `export { exec } from 'child_process'` re-exported through a barrel
 *   F4 — multi-hop alias re-export chain (A → B → consumer)
 */
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

const fixture = (rel: string) => path.join(__dirname, 'fixtures', 'cross-file', rel);

describe('Cross-file workflow', () => {
  test('F1: exported helper returning req.X taints downstream SQL sink', () => {
    const report = new BackendCodeReviewAnalyzer().analyze(fixture('f1-source-helper'));
    const sqli = report.findings.find((f) => f.ruleId === 'BCR-VAL-001');
    expect(sqli).toBeDefined();
    expect(sqli?.file).toContain('b.ts');
  });

  test('F3: re-exported exec from barrel fires command-execution', () => {
    const report = new BackendCodeReviewAnalyzer().analyze(fixture('f3-reexport-exec'));
    const cmd = report.findings.find((f) => f.ruleId === 'BCR-VAL-002');
    expect(cmd).toBeDefined();
    expect(cmd?.file).toContain('b.ts');
  });

  test('F4: multi-hop alias chain (A → B → consumer) resolves to exec', () => {
    const report = new BackendCodeReviewAnalyzer().analyze(fixture('f4-alias-chain'));
    const cmd = report.findings.find((f) => f.ruleId === 'BCR-VAL-002');
    expect(cmd).toBeDefined();
    expect(cmd?.file).toContain('c.ts');
  });

  test('Project context is null for single-file scans (no two-pass overhead)', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    analyzer.analyze(fixture('f3-reexport-exec/a.ts'));
    expect(analyzer.getProjectContext()).toBeNull();
  });

  test('Project context is built for directory scans', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    analyzer.analyze(fixture('f3-reexport-exec'));
    const ctx = analyzer.getProjectContext();
    expect(ctx).not.toBeNull();
    expect(ctx?.size).toBeGreaterThanOrEqual(2);
  });
});
