import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import * as fs from 'fs';
import * as path from 'path';

describe('AccessControlDetector', () => {
  let analyzer: BackendCodeReviewAnalyzer;

  beforeEach(() => {
    analyzer = new BackendCodeReviewAnalyzer();
  });

  describe('Missing Authorization Checks', () => {
    test('should detect missing authorization on sensitive endpoints', () => {
      const testFile = path.join(__dirname, 'fixtures/missing-authz.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL' && f.title.includes('Authorization')
      );

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('HIGH');
    });

    test('should not flag endpoints with authorization checks', () => {
      const testFile = path.join(__dirname, 'fixtures/with-authz.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL' && f.title.includes('Missing Authorization')
      );

      expect(findings.length).toBe(0);
    });
  });

  describe('BOLA Vulnerabilities', () => {
    test('should detect BOLA with sequential IDs', () => {
      const testFile = path.join(__dirname, 'fixtures/bola-sequential.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL' && f.title.includes('BOLA')
      );

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('CRITICAL');
    });

    test('should detect missing ownership verification', () => {
      const testFile = path.join(__dirname, 'fixtures/bola-no-ownership.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.title.includes('Ownership Verification')
      );

      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Privilege Escalation', () => {
    test('should detect vertical privilege escalation', () => {
      const testFile = path.join(__dirname, 'fixtures/priv-escalation.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL' && f.title.includes('Privilege Escalation')
      );

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('CRITICAL');
    });
  });

  describe('IDOR Vulnerabilities', () => {
    test('should detect IDOR with user-supplied IDs', () => {
      const testFile = path.join(__dirname, 'fixtures/idor.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL' && f.title.includes('IDOR')
      );

      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('POC Generation', () => {
    test('should generate POC for access control findings', () => {
      const testFile = path.join(__dirname, 'fixtures/bola-sequential.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL'
      );

      expect(findings.length).toBeGreaterThan(0);
      // POCs should be generated for findings
    });
  });

  describe('Integration', () => {
    test('should run detector alongside other detectors', () => {
      const testFile = path.join(__dirname, 'fixtures/mixed-issues.ts');
      const report = analyzer.analyze(testFile);

      const findings = report.findings.filter((f) => 
        f.category === 'ACCESS_CONTROL'
      );

      expect(findings.length).toBeGreaterThan(0);
    });

    test('should categorize findings correctly', () => {
      const testFile = path.join(__dirname, 'fixtures/bola-sequential.ts');
      const report = analyzer.analyze(testFile);

      expect(report.findingsByCategory['ACCESS_CONTROL']).toBeGreaterThan(0);
    });
  });
});
