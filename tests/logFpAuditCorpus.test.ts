/**
 * Log-mode FP audit corpus.
 *
 * Mirrors the code-mode contract: every log line in `tests/fixtures/fp-audit-logs/`
 * is a real-world bank log shape that LOOKS sensitive but is actually safe. The
 * default-mode log scanner must emit ZERO findings against the whole corpus.
 *
 * When this test fails, the failing finding IS a false positive. Either:
 *   - Tighten the rule precondition,
 *   - Demote the rule to heuristic so it's gated behind --include-heuristics,
 *   - Remove the line from the corpus if it should really fire.
 *
 * Comment lines (`#`) and blank lines are skipped.
 */
import * as fs from 'fs';
import * as path from 'path';
import { scanLogLine } from '../src/logs/logRules';
import { listRules } from '../src/rules/registry';

const corpusPath = path.join(__dirname, 'fixtures', 'fp-audit-logs', 'safe-log-lines.txt');

function loadCorpusLines(): Array<{ lineNumber: number; line: string }> {
  const raw = fs.readFileSync(corpusPath, 'utf-8').split(/\r?\n/);
  const out: Array<{ lineNumber: number; line: string }> = [];
  raw.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    if (trimmed.startsWith('#')) return;
    out.push({ lineNumber: index + 1, line });
  });
  return out;
}

describe('Log-mode FP audit corpus', () => {
  test('every safe-log-lines.txt entry produces zero findings under default rules', () => {
    const corpus = loadCorpusLines();
    expect(corpus.length).toBeGreaterThan(10);

    // Pull the heuristic ruleIds from the registry so this stays accurate as we add
    // rules. The default-mode contract: only non-heuristic LOG-* rules must fire zero.
    const HEURISTIC_RULES = new Set(
      listRules().filter((r) => r.heuristic).map((r) => r.id)
    );

    const offenders: Array<{ lineNumber: number; line: string; rules: string[] }> = [];
    for (const { lineNumber, line } of corpus) {
      const matches = scanLogLine(line);
      const nonHeuristic = matches.filter((m) => !HEURISTIC_RULES.has(m.ruleId));
      if (nonHeuristic.length > 0) {
        offenders.push({
          lineNumber,
          line,
          rules: nonHeuristic.map((m) => m.ruleId),
        });
      }
    }

    if (offenders.length > 0) {
      const summary = offenders
        .map((o) => `  L${o.lineNumber}  [${o.rules.join(',')}]  ${o.line.trim()}`)
        .join('\n');
      throw new Error(`Log FP corpus produced ${offenders.length} false-positive line(s):\n${summary}`);
    }
    expect(offenders.length).toBe(0);
  });
});
