import { ParameterValidationDetector } from '../../../src/detectors/validationDetector';
import { ASTParser } from '../../../src/parser/astParser';
import * as path from 'path';
import * as fs from 'fs';

describe('Validation Detector POC Generation', () => {
  const validationFixturePath = path.join(__dirname, '../../fixtures/vulnerable-validation.ts');
  const parser = new ASTParser(validationFixturePath);
  const sourceFile = parser.parse();

  if (!sourceFile) {
    throw new Error('Failed to parse validation fixture');
  }

  const detector = new ParameterValidationDetector(validationFixturePath, sourceFile, parser);

  describe('POC Generation for Injection Vulnerabilities', () => {
    it('should detect validation issues and generate POCs', () => {
      const result = detector.detect();
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should generate POCs for SQL injection vulnerabilities', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      // Some findings should have POCs if injection patterns are detected
      if (findingsWithPoc.length > 0) {
        const sqlInjectionPocs = findingsWithPoc.filter(
          f => f.injectionType === 'SQL Injection'
        );
        if (sqlInjectionPocs.length > 0) {
          const poc = sqlInjectionPocs[0].poc;
          expect(poc).toBeDefined();
          expect(poc?.vulnerabilityType).toBe('SQL Injection');
          expect(poc?.steps.length).toBeGreaterThan(0);
          expect(poc?.payloads.length).toBeGreaterThan(0);
        }
      }
    });

    it('should include exploitation steps in POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.steps).toBeDefined();
        expect(Array.isArray(poc?.steps)).toBe(true);
        expect(poc!.steps.length).toBeGreaterThan(0);
        
        // Check step structure
        poc?.steps.forEach(step => {
          expect(step.stepNumber).toBeDefined();
          expect(step.description).toBeDefined();
          expect(step.actor).toBeDefined();
        });
      });
    });

    it('should include payloads in POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.payloads).toBeDefined();
        expect(Array.isArray(poc?.payloads)).toBe(true);
        
        // Check payload structure
        poc?.payloads.forEach(payload => {
          expect(payload.name).toBeDefined();
          expect(payload.content).toBeDefined();
          expect(payload.contentType).toBeDefined();
          expect(payload.description).toBeDefined();
        });
      });
    });

    it('should include code flow in POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.codeFlow).toBeDefined();
        expect(poc?.codeFlow.diagram).toBeDefined();
        expect(poc?.codeFlow.components).toBeDefined();
        expect(poc?.codeFlow.connections).toBeDefined();
      });
    });

    it('should export POCs to markdown files', () => {
      const result = detector.detect();
      const outputDir = path.join(__dirname, '../../poc-reports-test');
      
      // Clean up if exists
      if (fs.existsSync(outputDir)) {
        fs.rmSync(outputDir, { recursive: true });
      }

      const generatedFiles = detector.exportPocsToMarkdown(result.findings, outputDir);
      
      // Check that markdown files were created
      if (result.findings.some(f => f.poc)) {
        expect(generatedFiles.length).toBeGreaterThan(0);
        
        // Verify files exist and contain markdown content
        generatedFiles.forEach(file => {
          expect(fs.existsSync(file)).toBe(true);
          const content = fs.readFileSync(file, 'utf-8');
          expect(content).toContain('#');
          expect(content).toContain('Severity');
          expect(content).toContain('Description');
        });
      }
      
      // Clean up
      if (fs.existsSync(outputDir)) {
        fs.rmSync(outputDir, { recursive: true });
      }
    });

    it('should retrieve generated POCs', () => {
      detector.detect();
      const pocs = detector.getGeneratedPocs();
      
      expect(Array.isArray(pocs)).toBe(true);
      
      pocs.forEach(poc => {
        expect(poc.title).toBeDefined();
        expect(poc.vulnerabilityType).toBeDefined();
        expect(poc.severity).toBeDefined();
        expect(poc.steps).toBeDefined();
        expect(poc.payloads).toBeDefined();
      });
    });
  });

  describe('POC Content Quality', () => {
    it('should include business impact in POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.businessImpact).toBeDefined();
        expect(poc?.businessImpact.length).toBeGreaterThan(0);
      });
    });

    it('should include technical impact in POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.technicalImpact).toBeDefined();
        expect(poc?.technicalImpact.length).toBeGreaterThan(0);
      });
    });

    it('should include remediation information in POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.remediationDescription).toBeDefined();
        expect(poc?.remediationDescription.length).toBeGreaterThan(0);
      });
    });

    it('should have proper timestamps for generated POCs', () => {
      const result = detector.detect();
      const findingsWithPoc = result.findings.filter(f => f.poc);
      
      findingsWithPoc.forEach(finding => {
        const poc = finding.poc;
        expect(poc?.generatedAt).toBeDefined();
        expect(poc?.generatedAt instanceof Date).toBe(true);
      });
    });
  });
});
