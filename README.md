# Backend Code Review Scanner

Static security scanner for Node.js and TypeScript backends.

It parses `.ts` and `.tsx` code locally with the TypeScript AST, prioritizes exploit-relevant findings, writes JSON or text reports, and exposes proof-of-concept helpers through the analyzer API.

## Highlights

- Local, static analysis only — no external API calls
- Default output is exploit-focused to keep reports lower-noise
- JSON and text report formats for CI and human review
- Structured runtime issue reporting for invalid targets, parse failures, and detector failures
- Programmatic POC export helpers for supported finding types

## Detector coverage

Current detector coverage includes checks for:

- authentication weaknesses
- validation and injection issues
- sensitive logging
- mass assignment
- access control flaws
- rate-limiting weaknesses
- business logic abuse patterns
- JWT validation bypasses
- API key and secret exposure
- unsafe deserialization and object hydration paths
- crypto weaknesses
- sensitive data exposure in responses
- cache poisoning risks
- message queue risks
- event stream risks

## Installation

```bash
npm install
npm run build
```

## Quick start

Run from source:

```bash
npm run dev -- --path ./src --output report.json
```

Run the compiled CLI:

```bash
node dist/index.js --path ./src --format json --output report.json
node dist/index.js --path ./src --format text --output report.txt
```

## CLI options

| Option | Alias | Description | Default |
| --- | --- | --- | --- |
| `--path` | `-p` | File or directory to analyze | `.` |
| `--output` | `-o` | Report file path | `code-review-<timestamp>.json` |
| `--format` | `-f` | Output format: `json` or `text` | `json` |
| `--include-heuristics` | `-a` | Include lower-confidence findings in addition to the default exploit-focused set | `false` |
| `--quiet` |  | Suppress non-error console output | `false` |
| `--verbose` |  | Enable verbose console logging | `false` |
| `--log-format` |  | Console log format: `text` or `json` | `text` |
| `--fail-on-runtime-errors` |  | Return a non-zero exit code when runtime analysis errors occur | `true` |

## Scan scope and defaults

- Broad directory scans analyze `.ts` and `.tsx` files.
- Broad scans respect `.gitignore` and skip generated or non-target paths such as `node_modules/`, `dist/`, `coverage/`, `tests/`, `__tests__/`, `pocs/`, and `*.d.ts` files.
- Explicit file and directory targets are still analyzed even when those paths would be skipped by a broad scan.
- Default reports keep the exploit-focused subset of findings. Use `--include-heuristics` to include lower-confidence or defense-in-depth checks.

## Exit behavior

- Exit `0`: no findings and no blocking runtime issues
- Exit `1`: findings detected, or runtime issues detected when `--fail-on-runtime-errors` is left enabled

## Report output

JSON reports include:

- `timestamp`
- `filesAnalyzed`
- `totalFindings`
- `findingsByCategory`
- `findingsBySeverity`
- `runtimeIssues`
- `runtimeIssuesByType`
- `hasRuntimeErrors`
- `findings[]` with severity, category, location, description, code snippet, and recommendation

Text reports include the same core data in a human-readable summary.

## Programmatic API and POCs

Inside this repository, you can use the analyzer directly:

```ts
import { BackendCodeReviewAnalyzer } from './src/analyzer';

const analyzer = new BackendCodeReviewAnalyzer();
const report = analyzer.analyze('./src');
const pocs = analyzer.getPocs();

analyzer.exportPocsAsMarkdown('./pocs');
analyzer.generateComprehensivePocReport('./pocs/comprehensive-report.md', 'My Service');
```

POC exports are currently generated for supported exploit-ready findings from the authentication, validation, and mass-assignment detectors. The comprehensive markdown report combines compatible POCs, payload guidance, and remediation tasks into one shareable artifact.

## Stability notes

- Runtime problems are surfaced as structured report entries instead of silently disappearing.
- Scan-scope rules and explicit-target behavior are covered by regression tests.
- `npm run build` recreates `dist/` before compiling to avoid stale build artifacts.

## Development

```bash
npm run build
npm test -- --runInBand
```

## Limitations

- Static analysis only
- Tuned for TypeScript backend code, not runtime traffic or live application behavior
- Default reporting intentionally favors higher-signal findings over full coverage
- Cross-file and inter-service semantic analysis is intentionally lightweight

## License

ISC
