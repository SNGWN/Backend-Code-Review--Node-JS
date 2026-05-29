/**
 * Renamed-dangerous-import coverage.
 *
 * Audit gap: `import { exec as runShell } from 'child_process'; runShell(req.body.x)`
 * was previously missed because detector regexes matched only the local call name.
 * The import alias resolver now maps `runShell` back to its canonical exported name.
 */
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

describe('Aliased dangerous imports', () => {
  test('command-execution rule fires when exec is renamed via import alias', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-aliased-imports.ts')
    );
    const cmd = report.findings.find((finding) => finding.ruleId === 'BCR-VAL-002');
    expect(cmd).toBeDefined();
    expect(cmd?.severity).toBe('CRITICAL');
  });

  test('file-system rule fires when readFileSync is renamed via import alias', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(
      path.join(__dirname, 'fixtures', 'vulnerable-aliased-imports.ts')
    );
    const pt = report.findings.find((finding) => finding.ruleId === 'BCR-PT-001');
    expect(pt).toBeDefined();
  });
});
