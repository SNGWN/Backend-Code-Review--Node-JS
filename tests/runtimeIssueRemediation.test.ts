import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { JSONReporter } from '../src/reporter';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { RuntimeIssue, RuntimeIssueType } from '../src/types';

/**
 * The scanner must not just *count* scan-time errors — it must show the relevant error
 * and a concrete fix. These tests pin that contract.
 */
describe('Runtime issue remediation', () => {
  const ALL_TYPES: RuntimeIssueType[] = [
    'INVALID_TARGET',
    'PARSE_FAILURE',
    'DETECTOR_FAILURE',
    'POC_EXPORT_FAILURE',
    'REPORT_WRITE_FAILURE',
    'FATAL_ANALYSIS_FAILURE',
  ];

  test('every runtime-issue type has a non-trivial, actionable fix', () => {
    for (const type of ALL_TYPES) {
      const fix = JSONReporter.remediationFor(type);
      expect(typeof fix).toBe('string');
      expect(fix.length).toBeGreaterThan(20);
    }
  });

  test('text report renders the error message and its Fix for a runtime issue', () => {
    const issue: RuntimeIssue = {
      type: 'PARSE_FAILURE',
      severity: 'ERROR',
      message: "':' expected.",
      file: 'src/broken.ts',
    };
    const report = JSONReporter.generateReport([], 1, [issue]);

    const out = path.join(os.tmpdir(), `bcr-rt-${process.pid}-${Date.now()}.txt`);
    JSONReporter.writeTextReport(report, out);
    const text = fs.readFileSync(out, 'utf-8');
    fs.unlinkSync(out);

    expect(text).toContain('Runtime Issues:');
    expect(text).toContain('PARSE_FAILURE');
    expect(text).toContain("':' expected.");
    expect(text).toContain('Fix:');
    expect(text).toContain(JSONReporter.remediationFor('PARSE_FAILURE'));
  });

  test('analyzing a missing path produces an INVALID_TARGET issue with a fix', () => {
    const report = new BackendCodeReviewAnalyzer().analyze(
      path.join(os.tmpdir(), `definitely-missing-${process.pid}.ts`)
    );
    expect(report.hasRuntimeErrors).toBe(true);
    const issue = report.runtimeIssues.find((i) => i.type === 'INVALID_TARGET');
    expect(issue).toBeDefined();
    expect(JSONReporter.remediationFor('INVALID_TARGET')).toMatch(/--path/);
  });

  test('analyzing a syntactically broken file produces a PARSE_FAILURE with a fix', () => {
    const broken = path.join(os.tmpdir(), `bcr-broken-${process.pid}-${Date.now()}.ts`);
    fs.writeFileSync(broken, 'export function broken( {\n  const x =\n', 'utf-8');
    const report = new BackendCodeReviewAnalyzer().analyze(broken);
    fs.unlinkSync(broken);

    const issue = report.runtimeIssues.find((i) => i.type === 'PARSE_FAILURE');
    expect(issue).toBeDefined();
    expect(issue?.severity).toBe('ERROR');
    expect(JSONReporter.remediationFor('PARSE_FAILURE')).toMatch(/syntax error/i);
  });
});
