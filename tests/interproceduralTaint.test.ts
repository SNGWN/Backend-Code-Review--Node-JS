import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import * as path from 'path';

/**
 * Locks in in-file inter-procedural taint: a value that becomes attacker-controlled inside a
 * helper function and is returned to the caller must still be tracked to a downstream sink.
 * This is the "tainted value flowing through functions" capability.
 */
describe('Inter-procedural taint', () => {
  let analyzer: BackendCodeReviewAnalyzer;

  beforeEach(() => {
    analyzer = new BackendCodeReviewAnalyzer();
  });

  test('flags SQL injection when the tainted value is laundered through a helper return', () => {
    const testFile = path.join(__dirname, 'fixtures/interproc-sqli.ts');
    const report = analyzer.analyze(testFile);

    const sqlFindings = report.findings.filter(
      (f) => f.ruleId === 'BCR-VAL-001' || /SQL Injection|SQL Query/i.test(f.title)
    );

    expect(sqlFindings.length).toBeGreaterThan(0);
  });

  test('does not flag a parameterized query as SQL injection', () => {
    const testFile = path.join(__dirname, 'fixtures/interproc-safe-param.ts');
    const report = analyzer.analyze(testFile, { includeHeuristics: true, minSeverity: 'LOW' });

    const sqlFindings = report.findings.filter(
      (f) => f.ruleId === 'BCR-VAL-001' || /SQL Injection|SQL Query/i.test(f.title)
    );

    expect(sqlFindings.length).toBe(0);
  });
});
