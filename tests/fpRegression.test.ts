/**
 * False-positive regression coverage.
 *
 * These tests pin the FP fixes called out by the architectural audit:
 *   - Identifier names containing "key"/"secret"/"username" do not flag as hardcoded
 *     credentials unless paired with a credential-shaped value.
 *   - `data`/`input`/`result` accidental token-collisions no longer poison taint.
 *   - `setTimeout(fn, ms)` (function-arg form) is not treated as dynamic code execution.
 *   - Substring sink names (`executeMigration`, `userQuery`, `rawValue`) are not flagged.
 *   - `res.json({ message: 'password updated' })`-style strings do not trigger data
 *     exposure on the word-anywhere match.
 *   - Utility `deleteCacheKey(k)` (no request data) does not trigger privilege escalation.
 *
 * If a future detector tweak regresses any of these, this test fails.
 */
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

const fixture = path.join(__dirname, 'fixtures', 'fp-regression-safe.ts');

describe('False-positive regression suite', () => {
  test('safe patterns produce zero default findings', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fixture);

    if (report.totalFindings > 0) {
      const summary = report.findings
        .map((finding) => `${finding.ruleId ?? '???'} ${finding.title} @ ${finding.file}:${finding.line}`)
        .join('\n');
      throw new Error(`Expected 0 findings, got ${report.totalFindings}:\n${summary}`);
    }

    expect(report.totalFindings).toBe(0);
  });

  test('every finding emitted by detectors carries a registry rule id', () => {
    // Cross-cuts every detector. Tests with bare-detector instantiation already exist;
    // this ensures the analyzer-level pipeline doesn't drop ruleId during enrichment.
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-auth.ts'),
      { includeHeuristics: true }
    );

    expect(report.totalFindings).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect(finding.ruleId).toMatch(/^BCR-/);
      expect(finding.fingerprint).toMatch(/^[a-f0-9]{16}$/);
      expect(Array.isArray(finding.cwe)).toBe(true);
      expect(typeof finding.owasp).toBe('string');
    }
  });

  test('--min-severity filters findings below the threshold', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const reportLow = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-jwt.ts'),
      { includeHeuristics: true, minSeverity: 'LOW' }
    );
    const reportCritical = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-jwt.ts'),
      { includeHeuristics: true, minSeverity: 'CRITICAL' }
    );

    expect(reportCritical.findings.every((finding) => finding.severity === 'CRITICAL')).toBe(true);
    expect(reportCritical.findings.length).toBeLessThan(reportLow.findings.length);
  });

  test('--disable-rule drops findings for the named rule', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const base = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-validation.ts'),
      { includeHeuristics: true }
    );
    const sqlBefore = base.findings.filter((finding) => finding.ruleId === 'BCR-VAL-001');
    expect(sqlBefore.length).toBeGreaterThan(0);

    const disabled = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-validation.ts'),
      { includeHeuristics: true, disabledRules: ['BCR-VAL-001'] }
    );
    expect(disabled.findings.every((finding) => finding.ruleId !== 'BCR-VAL-001')).toBe(true);
  });

  test('findings are sorted deterministically across runs', () => {
    const a = new BackendCodeReviewAnalyzer().analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-auth.ts'),
      { includeHeuristics: true }
    );
    const b = new BackendCodeReviewAnalyzer().analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-auth.ts'),
      { includeHeuristics: true }
    );
    expect(a.findings.map((finding) => finding.fingerprint)).toEqual(
      b.findings.map((finding) => finding.fingerprint)
    );
  });
});
