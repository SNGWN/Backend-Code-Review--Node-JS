import { JwtBypassDetector } from '../../../src/detectors/jwtBypassDetector';
import { ASTParser } from '../../../src/parser/astParser';
import * as path from 'path';

describe('JwtBypassDetector', () => {
  const fixturePath = path.join(__dirname, '../../fixtures/vulnerable-jwt.ts');
  let parser: ASTParser;
  let detector: JwtBypassDetector;

  beforeAll(() => {
    parser = new ASTParser(fixturePath);
    const sourceFile = parser.parse();
    if (!sourceFile) {
      throw new Error('Failed to parse fixture file');
    }
    detector = new JwtBypassDetector(fixturePath, sourceFile, parser);
  });

  describe('Detection Methods', () => {
    it('should detect missing signature verification', () => {
      const result = detector.detect();
      const missingVerificationFindings = result.findings.filter(
        f => f.title && f.title.includes('JWT Signature Not Verified')
      );
      expect(missingVerificationFindings.length).toBeGreaterThan(0);
      expect(missingVerificationFindings[0].severity).toBe('CRITICAL');
      expect(missingVerificationFindings[0].category).toBe('AUTHENTICATION');
    });

    it('should detect algorithm confusion attacks', () => {
      const result = detector.detect();
      const algorithmConfusionFindings = result.findings.filter(
        f => f.title && f.title.includes('Algorithm Confusion')
      );
      expect(algorithmConfusionFindings.length).toBeGreaterThan(0);
      expect(algorithmConfusionFindings[0].severity).toBe('CRITICAL');
    });

    it('should detect weak secret keys', () => {
      const result = detector.detect();
      const weakSecretFindings = result.findings.filter(
        f => f.title && f.title.includes('Weak JWT Secret')
      );
      expect(weakSecretFindings.length).toBeGreaterThan(0);
      expect(weakSecretFindings[0].severity).toMatch(/CRITICAL|HIGH/);
    });

    it('should detect missing kid validation', () => {
      const result = detector.detect();
      const missingKidFindings = result.findings.filter(
        f => f.title && f.title.includes('Missing Key ID')
      );
      expect(missingKidFindings.length).toBeGreaterThan(0);
      expect(missingKidFindings[0].severity).toBe('MEDIUM');
    });
  });

  describe('Finding Details', () => {
    it('should include proper file path in findings', () => {
      const result = detector.detect();
      expect(result.findings.length).toBeGreaterThan(0);
      result.findings.forEach(finding => {
        expect(finding.file).toBe(fixturePath);
      });
    });

    it('should include code snippets in findings', () => {
      const result = detector.detect();
      const findingsWithSnippets = result.findings.filter(f => f.code);
      expect(findingsWithSnippets.length).toBeGreaterThan(0);
    });

    it('should include recommendations in findings', () => {
      const result = detector.detect();
      const findingsWithRecommendations = result.findings.filter(
        f => f.recommendation && f.recommendation.length > 0
      );
      expect(findingsWithRecommendations.length).toBeGreaterThan(0);
    });

    it('should include line numbers for findings', () => {
      const result = detector.detect();
      expect(result.findings.length).toBeGreaterThan(0);
      result.findings.forEach(finding => {
        expect(finding.line).toBeGreaterThan(0);
      });
    });
  });

  describe('POC Generation', () => {
    it('should generate POCs for findings', () => {
      detector.detect();
      const pocs = detector.getPocs();
      expect(pocs.length).toBeGreaterThan(0);
    });

    it('should include exploitation steps in POCs', () => {
      detector.detect();
      const pocs = detector.getPocs();
      const pocsWithSteps = pocs.filter(poc => poc.steps && poc.steps.length > 0);
      expect(pocsWithSteps.length).toBeGreaterThan(0);
    });

    it('should include remediation code in POCs', () => {
      detector.detect();
      const pocs = detector.getPocs();
      const pocsWithRemediation = pocs.filter(poc => poc.remediationCode && poc.remediationCode.length > 0);
      expect(pocsWithRemediation.length).toBeGreaterThan(0);
    });
  });

  describe('Detector Results', () => {
    it('should return DetectorResult with findings array', () => {
      const result = detector.detect();
      expect(result).toHaveProperty('findings');
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should find multiple JWT vulnerabilities', () => {
      const result = detector.detect();
      expect(result.findings.length).toBeGreaterThanOrEqual(5);
    });

    it('should categorize all findings as AUTHENTICATION', () => {
      const result = detector.detect();
      result.findings.forEach(finding => {
        expect(finding.category).toBe('AUTHENTICATION');
      });
    });

    it('should mark critical findings appropriately', () => {
      const result = detector.detect();
      const criticalFindings = result.findings.filter(f => f.severity === 'CRITICAL');
      expect(criticalFindings.length).toBeGreaterThan(0);
    });
  });
});
