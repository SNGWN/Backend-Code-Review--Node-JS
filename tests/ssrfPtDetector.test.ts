/**
 * SSRF + Open Redirect + Path Traversal + Tagged-SQL + Weak-randomness coverage.
 *
 * The vulnerable fixture should emit ALL six findings under default mode (these are
 * high-signal rules, not heuristic). The safe fixture must emit zero — those checks
 * roll into the global FP audit corpus.
 */
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

const vulnerable = path.join(__dirname, 'fixtures', 'vulnerable-ssrf-pt.ts');

describe('SSRF / Open-redirect / Path-traversal / Tagged-SQL / Weak-randomness', () => {
  let report: ReturnType<BackendCodeReviewAnalyzer['analyze']>;

  beforeAll(() => {
    report = new BackendCodeReviewAnalyzer().analyze(vulnerable);
  });

  test('detects SSRF on fetch / axios with user-controlled URL', () => {
    const ssrf = report.findings.filter((finding) => finding.ruleId === 'BCR-SSRF-001');
    expect(ssrf.length).toBeGreaterThanOrEqual(2);
    expect(ssrf.every((finding) => finding.severity === 'CRITICAL')).toBe(true);
  });

  test('detects open redirect on res.redirect with user input', () => {
    const redirect = report.findings.find((finding) => finding.ruleId === 'BCR-REDIRECT-001');
    expect(redirect).toBeDefined();
    expect(redirect?.severity).toBe('HIGH');
  });

  test('detects path traversal on readFileSync with user-controlled name', () => {
    const pt = report.findings.find((finding) => finding.ruleId === 'BCR-PT-001');
    expect(pt).toBeDefined();
    expect(pt?.severity).toBe('CRITICAL');
  });

  test('detects tagged-template SQL injection on tainted substitution', () => {
    const sqli = report.findings.find((finding) => finding.ruleId === 'BCR-VAL-011');
    expect(sqli).toBeDefined();
    expect(sqli?.severity).toBe('CRITICAL');
  });

  test('detects weak-randomness identifiers (session/reset)', () => {
    const weak = report.findings.filter((finding) => finding.ruleId === 'BCR-CRYPTO-004');
    expect(weak.length).toBeGreaterThanOrEqual(2);
  });

  test('every new finding carries CWE + OWASP metadata', () => {
    const newRuleIds = ['BCR-SSRF-001', 'BCR-REDIRECT-001', 'BCR-PT-001', 'BCR-VAL-011', 'BCR-CRYPTO-004'];
    for (const ruleId of newRuleIds) {
      const finding = report.findings.find((f) => f.ruleId === ruleId);
      if (!finding) continue;
      expect(Array.isArray(finding.cwe)).toBe(true);
      expect(finding.cwe?.length).toBeGreaterThan(0);
      expect(typeof finding.owasp).toBe('string');
    }
  });
});
