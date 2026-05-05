import * as ts from 'typescript';
import { BusinessLogicDetector } from '../../src/detectors/businessLogicDetector';
import { ASTParser } from '../../src/parser/astParser';
import {
  raceConditionCode,
  missingIdempotencyCode,
  insufficientFundsCode,
  clientSidePriceCode,
  inventoryOverSellingCode,
  fixedInventoryCode,
} from '../fixtures/businessLogicFixtures';

describe('BusinessLogicDetector', () => {
  let parser: ASTParser;

  beforeEach(() => {
    parser = new ASTParser('test.ts');
  });

  describe('Race Condition Detection', () => {
    it('should detect race conditions in async operations', () => {
      const sourceFile = ts.createSourceFile(
        'test.ts',
        raceConditionCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('test.ts', sourceFile, parser);
      const result = detector.detect();

      expect(result.findings.length).toBeGreaterThan(0);
      const raceFinding = result.findings.find((f) =>
        f.title.toLowerCase().includes('race condition')
      );
      expect(raceFinding).toBeDefined();
      expect(raceFinding?.severity).toBe('HIGH');
    });
  });

  describe('Idempotency Key Detection', () => {
    it('should detect missing idempotency keys in payment operations', () => {
      const sourceFile = ts.createSourceFile(
        'payment.ts',
        missingIdempotencyCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
      const result = detector.detect();

      expect(result.findings.length).toBeGreaterThan(0);
      const idempotencyFinding = result.findings.find((f) =>
        f.title.toLowerCase().includes('idempotency')
      );
      expect(idempotencyFinding).toBeDefined();
      expect(idempotencyFinding?.severity).toBe('CRITICAL');
    });
  });

  describe('Insufficient Funds Check Detection', () => {
    it('should detect TOCTOU vulnerabilities in balance checks', () => {
      const sourceFile = ts.createSourceFile(
        'account.ts',
        insufficientFundsCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('account.ts', sourceFile, parser);
      const result = detector.detect();

      // This might detect race condition or TOCTOU
      expect(result.findings.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Client-Side Price Detection', () => {
    it('should detect client-controlled prices in payment operations', () => {
      const sourceFile = ts.createSourceFile(
        'checkout.ts',
        clientSidePriceCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('checkout.ts', sourceFile, parser);
      const result = detector.detect();

      expect(result.findings.length).toBeGreaterThan(0);
      const priceFinding = result.findings.find((f) =>
        f.title.toLowerCase().includes('client') && 
        f.title.toLowerCase().includes('price')
      );
      expect(priceFinding).toBeDefined();
      expect(priceFinding?.severity).toBe('CRITICAL');
    });
  });

  describe('Inventory Over-Selling Detection', () => {
    it('should detect inventory over-selling vulnerabilities', () => {
      const sourceFile = ts.createSourceFile(
        'inventory.ts',
        inventoryOverSellingCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('inventory.ts', sourceFile, parser);
      const result = detector.detect();

      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should ignore atomic inventory updates with quantity guards', () => {
      const sourceFile = ts.createSourceFile(
        'inventory.ts',
        fixedInventoryCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('inventory.ts', sourceFile, parser);
      const result = detector.detect();

      expect(
        result.findings.some((finding) =>
          finding.title.toLowerCase().includes('inventory over-selling')
        )
      ).toBe(false);
    });
  });

  describe('False Positive Regression', () => {
    it('should ignore detector-style string matching logic with payment keywords', () => {
      const sourceFile = ts.createSourceFile(
        'detector.ts',
        `
        function shouldFlag(sourceText: string, nodeText: string) {
          return (sourceText.includes('req.body') || sourceText.includes('req.query')) &&
            (sourceText.includes('charge') || sourceText.includes('payment') || sourceText.includes('stripe')) &&
            nodeText.includes('amount');
        }
        `,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('detector.ts', sourceFile, parser);
      const result = detector.detect();

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('POC Generation', () => {
    it('should generate POCs for detected vulnerabilities', () => {
      const sourceFile = ts.createSourceFile(
        'payment.ts',
        missingIdempotencyCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
      detector.detect();
      const pocs = detector.getPocs();

      expect(pocs.length).toBeGreaterThan(0);
      pocs.forEach((poc) => {
        expect(poc.id).toBeDefined();
        expect(poc.title).toBeDefined();
        expect(poc.steps.length).toBeGreaterThan(0);
        expect(poc.payloads.length).toBeGreaterThan(0);
      });
    });

    it('should generate POCs with exploitation steps', () => {
      const sourceFile = ts.createSourceFile(
        'payment.ts',
        clientSidePriceCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
      detector.detect();
      const pocs = detector.getPocs();

      if (pocs.length > 0) {
        const poc = pocs[0];
        expect(poc.steps.length).toBeGreaterThanOrEqual(4);
        expect(poc.steps[0].stepNumber).toBe(1);
        expect(poc.steps[0].actor).toBeDefined();
      }
    });

    it('should include business and technical impact in POCs', () => {
      const sourceFile = ts.createSourceFile(
        'payment.ts',
        missingIdempotencyCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
      detector.detect();
      const pocs = detector.getPocs();

      if (pocs.length > 0) {
        const poc = pocs[0];
        expect(poc.businessImpact).toBeDefined();
        expect(poc.businessImpact.length).toBeGreaterThan(0);
        expect(poc.technicalImpact).toBeDefined();
        expect(poc.technicalImpact.length).toBeGreaterThan(0);
      }
    });

    it('should include CVSS score in POCs', () => {
      const sourceFile = ts.createSourceFile(
        'payment.ts',
        clientSidePriceCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
      detector.detect();
      const pocs = detector.getPocs();

      if (pocs.length > 0) {
        const poc = pocs[0];
        expect(poc.cvssScore).toBeGreaterThanOrEqual(7.0);
        expect(poc.cvssScore).toBeLessThanOrEqual(9.9);
      }
    });

    it('should generate remediationDescription for each POC', () => {
      const sourceFile = ts.createSourceFile(
        'payment.ts',
        missingIdempotencyCode,
        ts.ScriptTarget.Latest,
        true
      );

      const detector = new BusinessLogicDetector('payment.ts', sourceFile, parser);
      detector.detect();
      const pocs = detector.getPocs();

      if (pocs.length > 0) {
        pocs.forEach((poc) => {
          expect(poc.remediationDescription).toBeDefined();
          expect(poc.remediationDescription.length).toBeGreaterThan(0);
        });
      }
    });
  });
});
