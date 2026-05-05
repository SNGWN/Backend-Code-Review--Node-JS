import * as ts from 'typescript';
import { ApiKeyDetector } from '../../src/detectors/apiKeyDetector';
import { ASTParser } from '../../src/parser/astParser';

describe('ApiKeyDetector', () => {
  let parser: ASTParser;

  beforeEach(() => {
    parser = new ASTParser('test.ts');
  });

  it('does not flag explanatory comments or placeholder secret labels as exposures', () => {
    const sourceFile = ts.createSourceFile(
      'safe-detector.ts',
      `
      /**
       * API Key/Secrets Exposure Detector
       * Hardcoded secrets, passwords, and API keys are dangerous.
       */
      const templateId = 'hardcoded-secret';
      const message = 'Move the secret into environment variables';
      logger.error('Failed to generate hardcoded secret POC');
      `,
      ts.ScriptTarget.Latest,
      true
    );

    const detector = new ApiKeyDetector('safe-detector.ts', sourceFile, parser);
    const result = detector.detect();

    expect(result.findings).toHaveLength(0);
  });

  it('detects concrete keys in comments and logs', () => {
    const sourceFile = ts.createSourceFile(
      'vulnerable.ts',
      `
      // Stripe secret: sk_live_4eC39HqLyjWDarhtT657G123
      console.log('Using key sk_live_4eC39HqLyjWDarhtT657G123');
      `,
      ts.ScriptTarget.Latest,
      true
    );

    const detector = new ApiKeyDetector('vulnerable.ts', sourceFile, parser);
    const result = detector.detect();
    const titles = result.findings.map((finding) => finding.title);

    expect(titles).toEqual(
      expect.arrayContaining(['Stripe Live Key in Comment', 'Stripe Live Key in Logs'])
    );
  });
});
