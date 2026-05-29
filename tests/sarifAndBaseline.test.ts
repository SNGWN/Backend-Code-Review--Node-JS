/**
 * SARIF + baseline + inline-suppression regression coverage.
 *
 * These tests pin the AppSec-engineer-facing surface:
 *   - SARIF 2.1.0 output validates the major structural invariants needed by GitHub
 *     code scanning and DefectDojo.
 *   - Baseline matches by content fingerprint (not line number), so trivial line
 *     drift does not churn the baseline.
 *   - Inline `// bcr-disable-next-line` and `// bcr-disable-line` suppress findings
 *     and surface them under `suppressedFindings`.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BackendCodeReviewAnalyzer } from '../src/analyzer';
import { Baseline } from '../src/rules/baseline';
import { SarifReporter } from '../src/reporter/sarif';

const vulnerableAuth = path.join(__dirname, 'fixtures', 'vulnerable-auth.ts');

describe('SARIF output', () => {
  test('emits a validly-shaped SARIF 2.1.0 document', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(vulnerableAuth, { includeHeuristics: true });
    const sarif = SarifReporter.build(report) as Record<string, unknown>;

    expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(sarif.version).toBe('2.1.0');

    const runs = sarif.runs as Array<Record<string, unknown>>;
    expect(Array.isArray(runs)).toBe(true);
    expect(runs.length).toBe(1);

    const driver = (runs[0].tool as Record<string, unknown>).driver as Record<string, unknown>;
    expect(driver.name).toBe('backend-code-review');
    const rules = driver.rules as Array<Record<string, unknown>>;
    expect(rules.length).toBeGreaterThan(0);

    const results = runs[0].results as Array<Record<string, unknown>>;
    expect(results.length).toBe(report.findings.length);
    for (const result of results) {
      expect(typeof result.ruleId).toBe('string');
      expect(typeof result.level).toBe('string');
      const fingerprints = result.partialFingerprints as Record<string, string>;
      expect(typeof fingerprints['primaryLocationLineHash/v1']).toBe('string');
    }
  });

  test('SARIF taxonomies live under runs[].taxonomies (schema-compliant placement)', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(vulnerableAuth, { includeHeuristics: true });
    const sarif = SarifReporter.build(report) as { runs: Array<Record<string, unknown>> };

    // Critical schema fix: taxa MUST live under runs[].taxonomies[], not directly on
    // runs[].tool.driver.taxa[]. The previous shape produced 55 schema violations.
    const driver = (sarif.runs[0].tool as Record<string, unknown>).driver as Record<string, unknown>;
    expect(driver.taxa).toBeUndefined();

    const taxonomies = sarif.runs[0].taxonomies as Array<{ name: string; taxa: unknown[] }>;
    expect(Array.isArray(taxonomies)).toBe(true);
    expect(taxonomies.length).toBeGreaterThanOrEqual(2);

    const taxonomyNames = taxonomies.map((t) => t.name);
    expect(taxonomyNames).toContain('CWE');
    expect(taxonomyNames).toContain('OWASP');

    for (const taxonomy of taxonomies) {
      expect(Array.isArray(taxonomy.taxa)).toBe(true);
      for (const taxon of taxonomy.taxa as Array<Record<string, unknown>>) {
        // Each taxon must NOT have a `toolComponent` field — that was the offending
        // additional property that broke strict SARIF ingesters.
        expect(taxon.toolComponent).toBeUndefined();
        expect(typeof taxon.id).toBe('string');
      }
    }
  });
});

describe('Baseline', () => {
  test('writing and matching round-trip suppresses prior findings', () => {
    const analyzer = new BackendCodeReviewAnalyzer();
    const firstRun = analyzer.analyze(vulnerableAuth, { includeHeuristics: true });
    expect(firstRun.totalFindings).toBeGreaterThan(0);

    const baselinePath = path.join(os.tmpdir(), `bcr-baseline-${Date.now()}.json`);
    try {
      Baseline.write(baselinePath, firstRun.findings);
      const persisted = JSON.parse(fs.readFileSync(baselinePath, 'utf-8'));
      expect(persisted.version).toBe(1);
      expect(persisted.entries.length).toBe(firstRun.totalFindings);

      const secondRun = new BackendCodeReviewAnalyzer().analyze(vulnerableAuth, {
        includeHeuristics: true,
        baselinePath,
      });
      expect(secondRun.totalFindings).toBe(0);
      expect(secondRun.suppressedFindings?.length).toBe(firstRun.totalFindings);
      expect(secondRun.suppressedFindings?.every((finding) => finding.suppressed?.source === 'baseline')).toBe(true);
    } finally {
      try {
        fs.unlinkSync(baselinePath);
      } catch {
        // best-effort cleanup
      }
    }
  });
});

describe('Inline suppression', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bcr-inline-'));

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  test('// bcr-disable-next-line drops the targeted rule', () => {
    const fixturePath = path.join(tempDir, 'inline-suppress.ts');
    fs.writeFileSync(
      fixturePath,
      [
        "const ENCRYPTION_KEY = 'k7Hf91p2QvX8r4Lc2NaB3Tg5Y6Wm0Eu9';",
        '// bcr-disable-next-line BCR-AUTH-004 -- triaged 2026-05-29, rotates monthly',
        "const SIGNING_KEY = 'mD3xY7q1WnP8tCv6Hk4Lj2Bg0RsZ5Eu9';",
      ].join('\n') + '\n',
      'utf-8'
    );

    const analyzer = new BackendCodeReviewAnalyzer();
    const report = analyzer.analyze(fixturePath);

    const visibleSigningKeyFinding = report.findings.find((finding) => finding.line === 3);
    expect(visibleSigningKeyFinding).toBeUndefined();

    const suppressedSigning = report.suppressedFindings?.find((finding) => finding.line === 3);
    expect(suppressedSigning?.suppressed?.source).toBe('inline');
    expect(suppressedSigning?.suppressed?.reason).toContain('triaged');
  });
});
