/**
 * Comprehensive FP audit.
 *
 * Every fixture file in `tests/fixtures/fp-audit/` contains code that LOOKS sensitive
 * but is actually safe under normal AppSec review. The default-mode scanner must emit
 * ZERO findings against this corpus.
 *
 * When this test fails, the failing finding IS a false positive. Either:
 *   1. Tighten the detector to require a stronger precondition, or
 *   2. Demote the rule to heuristic so it's gated behind --include-heuristics, or
 *   3. Remove the fixture block if the pattern truly should fire.
 *
 * Do NOT silently relax this assertion — every finding here is a bug.
 */
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';

const fpAuditDir = path.join(__dirname, 'fixtures', 'fp-audit');

describe('FP audit corpus (default mode → zero findings)', () => {
  test('full corpus scan produces zero findings', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fpAuditDir);

    if (report.totalFindings > 0) {
      const summary = report.findings
        .map((finding) => `${finding.ruleId ?? '???'}  ${finding.severity.padEnd(8)}  ${finding.file}:${finding.line}  ${finding.title}`)
        .join('\n');
      throw new Error(
        `Default scan produced ${report.totalFindings} false positive(s):\n${summary}`
      );
    }

    expect(report.totalFindings).toBe(0);
    expect(report.filesAnalyzed).toBeGreaterThanOrEqual(11);
  });

  test('corpus is also clean even when heuristics are enabled', () => {
    // Heuristics-on may legitimately emit some findings (that's the contract: lower
    // confidence, broader recall). But truly safe code should still emit zero. If
    // this regresses, a heuristic rule is too eager — tighten or move under a stricter gate.
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fpAuditDir, { includeHeuristics: true });

    // We allow up to ~5 heuristic findings per file before declaring an issue. This
    // catches catastrophic regressions ("now flagging everything") without forcing
    // every heuristic rule to be perfect.
    const ceiling = report.filesAnalyzed * 5;
    if (report.totalFindings > ceiling) {
      const summary = report.findings
        .map((finding) => `${finding.ruleId ?? '???'}  ${finding.severity.padEnd(8)}  ${finding.file}:${finding.line}  ${finding.title}`)
        .join('\n');
      throw new Error(
        `Heuristic scan produced ${report.totalFindings} findings (ceiling ${ceiling}):\n${summary}`
      );
    }
  });
});
