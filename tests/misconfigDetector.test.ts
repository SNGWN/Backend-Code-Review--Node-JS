/**
 * Misconfiguration + new-rule coverage.
 *
 * Verifies that each new rule (BCR-MISC-001..004, BCR-CRYPTO-005, BCR-MA-006, BCR-VAL-012)
 * fires on its respective vulnerable shape. The matching FP corpus file
 * `fp-audit/misconfig-safe.ts` is exercised by the global FP-zero test.
 */
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

const fixture = path.join(__dirname, 'fixtures', 'vulnerable-misconfig.ts');

describe('Misconfiguration + new-detector coverage', () => {
  let report: ReturnType<BackendCodeReviewAnalyzer['analyze']>;
  let heuristicReport: ReturnType<BackendCodeReviewAnalyzer['analyze']>;
  beforeAll(() => {
    report = new BackendCodeReviewAnalyzer().analyze(fixture);
    heuristicReport = new BackendCodeReviewAnalyzer().analyze(fixture, { includeHeuristics: true });
  });

  test('BCR-MISC-001 fires on cors({ origin: "*" })', () => {
    const findings = report.findings.filter((f) => f.ruleId === 'BCR-MISC-001');
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  // BCR-MISC-002/003 are heuristic (lower-confidence "defaults could be reasonable" rules).
  test('BCR-MISC-002 fires on express.json() without limit (heuristic mode)', () => {
    const findings = heuristicReport.findings.filter((f) => f.ruleId === 'BCR-MISC-002');
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  test('BCR-MISC-003 fires on helmet() with no options (heuristic mode)', () => {
    const findings = heuristicReport.findings.filter((f) => f.ruleId === 'BCR-MISC-003');
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  test('BCR-MISC-004 fires on bcrypt.hash(pw, < 10)', () => {
    const findings = report.findings.filter((f) => f.ruleId === 'BCR-MISC-004');
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.every((f) => f.severity === 'HIGH')).toBe(true);
  });

  test('BCR-CRYPTO-005 fires on crypto.createCipher', () => {
    const finding = report.findings.find((f) => f.ruleId === 'BCR-CRYPTO-005');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  test('BCR-MA-006 fires on service.createUser(req.body) without validation', () => {
    const finding = report.findings.find((f) => f.ruleId === 'BCR-MA-006');
    expect(finding).toBeDefined();
  });

  test('BCR-VAL-012 fires on Buffer.from(<user>, "base64").toString()', () => {
    const finding = report.findings.find((f) => f.ruleId === 'BCR-VAL-012');
    expect(finding).toBeDefined();
  });
});
