import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

describe('Phase 2 detector integration regression', () => {
  const fixture = (name: string) => path.join(__dirname, 'fixtures', name);

  test('detects exploitable API key exposure paths in service fixtures', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fixture('vulnerable-api-keys.ts'));
    const apiKeyFindings = report.findings.filter((finding) => finding.category === 'API_KEY_EXPOSURE');
    const titles = apiKeyFindings.map((finding) => finding.title);

    expect(apiKeyFindings.length).toBeGreaterThanOrEqual(8);
    expect(titles).toEqual(
      expect.arrayContaining([
        'Hardcoded Stripe Live Key',
        'Stripe Live Key in Logs',
        'Database Credentials in Connection String',
      ])
    );
    expect(report.findingsByCategory.API_KEY_EXPOSURE).toBe(apiKeyFindings.length);
    expect(apiKeyFindings.every((finding) => ['HIGH', 'CRITICAL'].includes(finding.severity))).toBe(true);
  });

  test('keeps exploit-focused crypto and data exposure findings visible by default', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fixture('vulnerable-phase2-account-service.ts'));
    const cryptoFindings = report.findings.filter((finding) => finding.category === 'CRYPTO_WEAKNESS');
    const dataExposureFindings = report.findings.filter((finding) => finding.category === 'DATA_EXPOSURE');

    expect(cryptoFindings.map((finding) => finding.title)).toEqual(
      expect.arrayContaining([
        'Predictable token with Math.random()',
        'Hardcoded cryptographic key',
      ])
    );
    expect(cryptoFindings.some((finding) => finding.title === 'Weak hashing: md5')).toBe(false);
    expect(dataExposureFindings.map((finding) => finding.title)).toEqual(
      expect.arrayContaining([
        'Sensitive field "password" exposed in response',
        'Sensitive field "apiKey" exposed in response',
        'Sensitive field "ssn" exposed in response',
      ])
    );
    expect(report.findingsByCategory.CRYPTO_WEAKNESS).toBe(cryptoFindings.length);
    expect(report.findingsByCategory.DATA_EXPOSURE).toBe(dataExposureFindings.length);
  });

  test('surfaces critical deserialization exploit paths by default and keeps broader heuristics optional', () => {
    const defaultAnalyzer = new BackendCodeReviewAnalyzer();
    const defaultReport = defaultAnalyzer.analyze(fixture('vulnerable-phase2-deserialization.ts'));
    const heuristicAnalyzer = new BackendCodeReviewAnalyzer();
    const heuristicReport = heuristicAnalyzer.analyze(fixture('vulnerable-phase2-deserialization.ts'), {
      includeHeuristics: true,
    });
    const defaultTitles = defaultReport.findings
      .filter((finding) => finding.category === 'VALIDATION')
      .map((finding) => finding.title);
    const heuristicTitles = heuristicReport.findings
      .filter((finding) => finding.category === 'VALIDATION')
      .map((finding) => finding.title);

    expect(defaultTitles).toEqual(
      expect.arrayContaining([
        'Unsafe JSON.parse with User Input',
        'Code Injection via eval() Deserialization',
      ])
    );
    expect(defaultTitles).not.toEqual(
      expect.arrayContaining([
        'Unsafe Object.assign with Untrusted Data',
        'Unsafe Object Spread with Untrusted Data',
      ])
    );
    expect(heuristicTitles).toEqual(
      expect.arrayContaining([
        'Unsafe JSON.parse with User Input',
        'Code Injection via eval() Deserialization',
        'Unsafe Object.assign with Untrusted Data',
        'Unsafe Object Spread with Untrusted Data',
      ])
    );
    expect(heuristicReport.totalFindings).toBeGreaterThan(defaultReport.totalFindings);
  });

  test('keeps medium-signal JWT heuristics out of the default exploit-focused report', () => {
    const defaultAnalyzer = new BackendCodeReviewAnalyzer();
    const defaultReport = defaultAnalyzer.analyze(fixture('vulnerable-jwt.ts'));
    const defaultPocs = defaultAnalyzer.getPocs();
    const heuristicAnalyzer = new BackendCodeReviewAnalyzer();
    const heuristicReport = heuristicAnalyzer.analyze(fixture('vulnerable-jwt.ts'), {
      includeHeuristics: true,
    });
    const heuristicPocs = heuristicAnalyzer.getPocs();
    const defaultTitles = defaultReport.findings.map((finding) => finding.title);
    const heuristicTitles = heuristicReport.findings.map((finding) => finding.title);

    expect(defaultTitles).not.toContain('Missing Key ID (kid) Validation');
    expect(heuristicTitles).toContain('Missing Key ID (kid) Validation');
    expect(defaultPocs.map((poc) => poc.title)).not.toContain('Missing Key ID (kid) Validation');
    expect(heuristicPocs.map((poc) => poc.title)).toContain('Missing Key ID (kid) Validation');
    expect(heuristicReport.totalFindings).toBeGreaterThan(defaultReport.totalFindings);
  });

  test('does not flag hardened phase 2 helper patterns as exploitable', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fixture('safe-phase2-account-service.ts'));

    expect(report.totalFindings).toBe(0);
    expect(report.findingsByCategory.CRYPTO_WEAKNESS).toBe(0);
    expect(report.findingsByCategory.DATA_EXPOSURE).toBe(0);
    expect(report.findingsByCategory.API_KEY_EXPOSURE).toBe(0);
    expect(report.findingsByCategory.VALIDATION).toBe(0);
  });
});
