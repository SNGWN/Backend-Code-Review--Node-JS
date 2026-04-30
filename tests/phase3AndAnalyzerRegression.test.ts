import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { AuthenticationDetector } from '../src/detectors/authDetector';

describe('Phase 3 Detectors & Analyzer Regression', () => {
  describe('Phase 3 category mapping', () => {
    test('detects cache poisoning findings under CACHE_POISONING', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const testFile = path.join(__dirname, 'fixtures/vulnerable-cache-poisoning.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => f.category === 'CACHE_POISONING');
      expect(findings.length).toBeGreaterThan(0);
      expect(report.findingsByCategory.CACHE_POISONING).toBeGreaterThan(0);
    });

    test('detects message queue findings under MESSAGE_QUEUE', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const testFile = path.join(__dirname, 'fixtures/vulnerable-message-queue.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => f.category === 'MESSAGE_QUEUE');
      expect(findings.length).toBeGreaterThan(0);
      expect(report.findingsByCategory.MESSAGE_QUEUE).toBeGreaterThan(0);
    });

    test('detects event stream findings under EVENT_STREAM', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const testFile = path.join(__dirname, 'fixtures/vulnerable-event-stream.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => f.category === 'EVENT_STREAM');
      expect(findings.length).toBeGreaterThan(0);
      expect(report.findingsByCategory.EVENT_STREAM).toBeGreaterThan(0);
    });

    test('does not flag hardened phase-3 patterns as exploitable', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const safeFixtures = [
        path.join(__dirname, 'fixtures/safe-cache-poisoning.ts'),
        path.join(__dirname, 'fixtures/safe-message-queue.ts'),
        path.join(__dirname, 'fixtures/safe-event-stream.ts'),
      ];

      for (const testFile of safeFixtures) {
        const report = analyzer.analyze(testFile);
        const phase3Findings = report.findings.filter((f) =>
          ['CACHE_POISONING', 'MESSAGE_QUEUE', 'EVENT_STREAM'].includes(f.category)
        );
        expect(phase3Findings.length).toBe(0);
      }
    });
  });

  describe('Analyzer run-state reset', () => {
    test('does not accumulate findings across multiple analyze() runs on same instance', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const testFile = path.join(__dirname, 'fixtures/vulnerable-auth.ts');

      const firstRun = analyzer.analyze(testFile);
      const secondRun = analyzer.analyze(testFile);

      expect(firstRun.totalFindings).toBeGreaterThan(0);
      expect(secondRun.totalFindings).toBe(firstRun.totalFindings);
      expect(secondRun.findingsByCategory).toEqual(firstRun.findingsByCategory);
    });
  });

  describe('Exploitable-only filtering', () => {
    test('returns only exploitable/chainable subset', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const testFile = path.join(__dirname, 'fixtures/vulnerable-message-queue.ts');
      const report = analyzer.analyze(testFile);
      const exploitable = analyzer.getExploitableFindings(report.findings);

      expect(exploitable.length).toBeGreaterThan(0);
      expect(exploitable.length).toBeLessThanOrEqual(report.findings.length);
      expect(exploitable.every((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')).toBe(true);
    });
  });

  describe('Exploit-focused default reporting', () => {
    test('does not emit low-signal hygiene findings by default', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const testFile = path.join(__dirname, 'fixtures/low-signal-only.ts');
      const report = analyzer.analyze(testFile);

      expect(report.totalFindings).toBe(0);
    });
  });

  describe('Runtime issue reporting', () => {
    test('reports invalid target paths as runtime errors', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const report = analyzer.analyze(path.join(__dirname, 'fixtures', 'missing-target.ts'));

      expect(report.totalFindings).toBe(0);
      expect(report.hasRuntimeErrors).toBe(true);
      expect(report.runtimeIssuesByType.INVALID_TARGET).toBe(1);
      expect(report.runtimeIssues[0]?.type).toBe('INVALID_TARGET');
    });

    test('reports parse failures as runtime errors', () => {
      const analyzer = new BackendCodeReviewAnalyzer();
      const report = analyzer.analyze(path.join(__dirname, 'fixtures', 'syntax-error.ts'));

      expect(report.totalFindings).toBe(0);
      expect(report.hasRuntimeErrors).toBe(true);
      expect(report.runtimeIssuesByType.PARSE_FAILURE).toBe(1);
      expect(report.runtimeIssues[0]?.type).toBe('PARSE_FAILURE');
    });

    test('isolates detector failures into runtime issues', () => {
      const spy = jest
        .spyOn(AuthenticationDetector.prototype, 'detect')
        .mockImplementationOnce(() => {
          throw new Error('detector boom');
        });

      try {
        const analyzer = new BackendCodeReviewAnalyzer();
        const report = analyzer.analyze(path.join(__dirname, 'fixtures', 'vulnerable-auth.ts'));

        expect(report.hasRuntimeErrors).toBe(true);
        expect(report.runtimeIssuesByType.DETECTOR_FAILURE).toBe(1);
        expect(report.runtimeIssues[0]).toMatchObject({
          type: 'DETECTOR_FAILURE',
          detector: 'AuthenticationDetector',
        });
      } finally {
        spy.mockRestore();
      }
    });
  });
});
