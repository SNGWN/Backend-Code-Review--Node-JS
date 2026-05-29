/**
 * CLI runner integration tests via subprocess.
 *
 * We can't import `runCli()` in-process under ts-jest because yargs v18 ships ESM-only
 * subpath exports (`yargs/yargs`) that Jest's CJS runtime cannot evaluate. Spawning
 * `node dist/index.js` instead exercises the real packaged entrypoint — the same
 * code path users hit — which is arguably better coverage anyway.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

const repoRoot = path.resolve(__dirname, '..');
const bin = path.join(repoRoot, 'dist', 'index.js');
const fixturesDir = path.join(repoRoot, 'tests', 'fixtures');

const vulnerableAuth = path.join(fixturesDir, 'vulnerable-auth.ts');
const vulnerableValidation = path.join(fixturesDir, 'vulnerable-validation.ts');
const lowSignal = path.join(fixturesDir, 'low-signal-only.ts');
const fpCorpus = path.join(fixturesDir, 'fp-audit');

function tmp(name: string): string {
  return path.join(os.tmpdir(), `bcr-cli-${Date.now()}-${Math.random().toString(36).slice(2)}-${name}`);
}

function run(args: string[]): { code: number; stdout: string; stderr: string } {
  const result = spawnSync('node', [bin, ...args], { encoding: 'utf-8' });
  return { code: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

describe('CLI runner (subprocess)', () => {
  beforeAll(() => {
    if (!fs.existsSync(bin)) {
      throw new Error(`dist/index.js missing — run \`npm run build\` first. (expected at ${bin})`);
    }
  });

  test('default scan over FP corpus exits 0', () => {
    const out = tmp('fp.json');
    const r = run(['--path', fpCorpus, '--format', 'json', '--output', out, '--quiet']);
    expect(r.code).toBe(0);
    const report = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(report.totalFindings).toBe(0);
  });

  test('vulnerable fixture exits 1 with default --fail-on=HIGH', () => {
    const out = tmp('vuln.json');
    const r = run(['--path', vulnerableAuth, '--format', 'json', '--output', out, '--quiet']);
    expect(r.code).toBe(1);
  });

  test('--fail-on CRITICAL: zero exit when only HIGH findings present', () => {
    const out = tmp('low.json');
    const r = run(['--path', lowSignal, '--format', 'json', '--output', out, '--fail-on', 'CRITICAL', '--quiet']);
    expect(r.code).toBe(0);
  });

  test('--fail-on CRITICAL: exits 1 when CRITICAL present', () => {
    const out = tmp('crit.json');
    const r = run(['--path', vulnerableValidation, '--format', 'json', '--output', out, '--fail-on', 'CRITICAL', '--quiet']);
    expect(r.code).toBe(1);
  });

  test('--min-severity CRITICAL filters findings', () => {
    const out = tmp('min.json');
    const r = run(['--path', vulnerableAuth, '--format', 'json', '--output', out, '--min-severity', 'CRITICAL', '--include-heuristics', '--quiet']);
    expect([0, 1]).toContain(r.code);
    const report = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(report.findings.every((f: { severity: string }) => f.severity === 'CRITICAL')).toBe(true);
  });

  test('--disable-rule with comma list', () => {
    const out = tmp('disable.json');
    run([
      '--path', vulnerableValidation, '--format', 'json', '--output', out,
      '--disable-rule', 'BCR-VAL-001,BCR-VAL-005', '--quiet',
    ]);
    const report = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(report.findings.every((f: { ruleId: string }) => f.ruleId !== 'BCR-VAL-001' && f.ruleId !== 'BCR-VAL-005')).toBe(true);
  });

  test('invalid --format exits 2 (usage error)', () => {
    const r = run(['--path', lowSignal, '--format', 'unknown', '--quiet']);
    expect(r.code).toBe(2);
  });

  test('invalid --min-severity exits 2', () => {
    const r = run(['--path', lowSignal, '--min-severity', 'EXTRA', '--quiet']);
    expect(r.code).toBe(2);
  });

  test('unknown flag is rejected by yargs strict mode', () => {
    const r = run(['--path', lowSignal, '--bogus-flag', '--quiet']);
    expect(r.code).not.toBe(0);
  });

  test('--baseline missing file exits non-zero (no silent degrade)', () => {
    const r = run([
      '--path', vulnerableAuth, '--format', 'json', '--output', tmp('b.json'),
      '--baseline', '/tmp/bcr-does-not-exist-' + Date.now() + '.json', '--quiet',
    ]);
    expect(r.code).not.toBe(0);
  });

  test('--update-baseline writes baseline and exits 0', () => {
    const baselinePath = tmp('baseline-out.json');
    const r = run([
      '--path', vulnerableAuth, '--update-baseline', '--baseline', baselinePath, '--quiet',
    ]);
    expect(r.code).toBe(0);
    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf-8'));
    expect(baseline.version).toBe(1);
    expect(Array.isArray(baseline.entries)).toBe(true);
    expect(baseline.entries.length).toBeGreaterThan(0);
  });

  test('two consecutive --update-baseline runs produce byte-identical files', () => {
    const b1 = tmp('baseline-1.json');
    const b2 = tmp('baseline-2.json');
    run(['--path', vulnerableAuth, '--update-baseline', '--baseline', b1, '--quiet']);
    run(['--path', vulnerableAuth, '--update-baseline', '--baseline', b2, '--quiet']);
    expect(fs.readFileSync(b1, 'utf-8')).toBe(fs.readFileSync(b2, 'utf-8'));
  });

  test('--list-rules writes JSON catalog to stdout', () => {
    const r = run(['--list-rules', '--quiet']);
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(40);
    for (const rule of parsed.slice(0, 5)) {
      expect(rule.id).toMatch(/^BCR-/);
      expect(typeof rule.title).toBe('string');
      expect(Array.isArray(rule.cwe)).toBe(true);
    }
  });

  test('--help exits 0 and includes Examples', () => {
    const r = run(['--help']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('--format');
    expect(r.stdout).toContain('Examples');
  });
});
