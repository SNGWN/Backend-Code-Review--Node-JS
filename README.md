# Backend Code Review Scanner (Node.js + TypeScript AST)

Static security scanner for backend TypeScript/Node.js microservices.  
It analyzes source code using the TypeScript AST, prioritizes actually exploitable or chainable backend flaws, and generates actionable findings (with optional POC artifacts via the analyzer API).

## Why this project

- Runs fully local (no external API calls)
- Targets backend security issues common in microservices
- Produces CI-friendly JSON output
- Includes detector-level exploit context (severity, code location, remediation, and POC data model)
- Comprehensive POC exports now include exploit-chain summaries, payload reliability, and prioritized remediation tasks

## Current coverage

The scanner currently includes these detector families:

1. Authentication
2. Validation
3. Logging
4. Mass Assignment
5. Access Control
6. Rate Limiting
7. Business Logic
8. JWT validation bypasses
9. API key and secret exposure
10. Deserialization and object-merge abuse
11. Crypto weakness
12. Data exposure
13. Cache Poisoning (Phase 3)
14. Message Queue Risks (Phase 3)
15. Event Stream Risks (Phase 3)

## Phase 2 detector set

Phase 2 extends the backend/microservice coverage with exploit-oriented checks around auth tokens, secrets handling, unsafe object hydration, and response leakage.

- **JWT validation bypasses** (`AUTHENTICATION` findings): missing `jwt.verify`, `none` algorithm acceptance, HS256/public-key confusion, weak JWT secrets, disabled expiration checks, and cached decoded tokens. The current medium-signal `kid` validation check is only included with `--include-heuristics`.
- **API key / secret exposure** (`API_KEY_EXPOSURE`): hardcoded service keys, secrets in config objects and default parameters, secrets left in comments/logs/error strings, and database connection strings with embedded credentials.
- **Deserialization / prototype-pollution paths** (`VALIDATION` findings): untrusted `JSON.parse`, `eval`/`Function` deserialization, `__proto__` / `constructor.prototype` writes, and gadget-style object handling. Broader merge helpers such as unsafe `Object.assign` and object spread are available when `--include-heuristics` is enabled.
- **Crypto weakness** (`CRYPTO_WEAKNESS`): predictable token generation via `Math.random()` and hardcoded cryptographic keys. Lower-signal weak-hash detections stay out of the default exploit-focused view unless they are tied to sensitive use.
- **Data exposure** (`DATA_EXPOSURE`): backend handlers that return sensitive fields such as `password`, `apiKey`, `secret`, `token`, `creditCard`, or `ssn` in API responses.

### Default vs heuristic-inclusive output

By default, the report keeps the exploit-focused subset that is intended for CI gates and triage. In the current Phase 2 set, that means clearly exploitable paths such as:

- `jwt.decode()` without verification
- `JSON.parse(req.body...)` / `eval(req.body...)`
- hardcoded or logged credentials
- predictable tokens and hardcoded crypto keys
- sensitive fields returned to clients

Enable `--include-heuristics` when you also want lower-confidence or defense-in-depth findings that are implemented but intentionally excluded from the default report, such as:

- `Missing Key ID (kid) Validation`
- `Unsafe Object.assign with Untrusted Data`
- `Unsafe Object Spread with Untrusted Data`

This detector family/report-category split is intentional in the current implementation: JWT issues are emitted under `AUTHENTICATION`, and deserialization/object hydration issues are emitted under `VALIDATION`.

### Phase 1 detector behavior (validated by tests)

Phase 1 is intentionally exploit-focused. By default, the analyzer keeps the higher-signal findings that represent realistic backend abuse paths.

| Detector | Default behavior | POC behavior |
|---|---|---|
| Authentication | Flags hardcoded secrets, unverified token usage, and missing auth guards on sensitive functions | Hardcoded secret findings generate credential-theft POCs with payloads, exploit steps, and remediation code |
| Validation | Flags untrusted request data reaching raw SQL, command/code execution, and file-system sinks | Concrete injection findings carry POCs with payloads, code-flow diagrams, and parameterized-query remediation guidance |
| Logging | Keeps sensitive-data-in-logs and log-injection findings that still matter to attackers | No standalone POC export; these remain report-only findings |
| Mass Assignment | Flags direct object assignment, unvalidated field assignment, and prototype/constructor abuse patterns | Exploitable findings generate mass-assignment / object-pollution POCs, including prototype-pollution payloads |
| Rate Limiting | Default report suppresses lower-signal hygiene gaps and keeps bypass-oriented findings such as header manipulation and distributed bypass | No standalone POC export; findings stay focused on exploitable bypass scenarios |

Tested Phase 1 behavior currently includes:

- hardcoded secret POCs for authentication findings
- SQL injection POCs attached directly to validation findings
- high-signal logging findings preserved without noisy low-value output
- prototype/constructor mass-assignment findings with exploit payloads
- default rate-limit reporting limited to exploit-relevant bypass cases

## Architecture

Core flow:

1. **File discovery** (`FileHelper`) recursively finds `.ts/.tsx`
2. **Parsing** (`ASTParser`) builds AST per file
3. **Detection** (`src/detectors/*`) runs pattern + context checks
4. **Aggregation** (`BackendCodeReviewAnalyzer`) merges findings/POCs
5. **Reporting** (`JSONReporter`) writes report + CLI summary

Main entry points:

- CLI: `src/index.ts`
- Orchestrator: `src/analyzer.ts`
- Reporter: `src/reporter.ts`
- Types: `src/types.ts`, `src/poc/types.ts`

## Installation

```bash
npm install
npm run build
```

Requirements:

- Node.js 18+ recommended
- npm

## CLI usage

### Run from source

```bash
npm run dev -- --path ./src --output report.json
```

### Run compiled binary

```bash
npm run build
node dist/index.js --path ./src --output report.json
```

### Options

| Option | Alias | Description | Default |
|---|---|---|---|
| `--path` | `-p` | File or directory to analyze | `.` |
| `--output` | `-o` | Report file path | `code-review-<timestamp>.json` |
| `--format` | `-f` | Output format (`json`, `text`) | `json` |
| `--include-heuristics` | `-a` | Include lower-confidence heuristic findings in addition to the default exploit-focused output | `false` |
| `--quiet` |  | Suppress non-error console output | `false` |
| `--verbose` |  | Enable verbose console logging | `false` |
| `--log-format` |  | Console log format (`text`, `json`) | `text` |
| `--fail-on-runtime-errors` |  | Return a non-zero exit code when parse/setup/runtime errors occur | `true` |

## Exit behavior

- Exit `0`: no findings and no blocking runtime issues
- Exit `1`: findings detected, runtime errors detected (default), or fatal/report-write failure

This makes it suitable for CI security gates while still surfacing parser/detector failures as structured runtime issues.

## Output format

Generated report includes:

- `timestamp`
- `filesAnalyzed`
- `totalFindings`
- `findingsByCategory`
- `findingsBySeverity`
- `runtimeIssues`
- `runtimeIssuesByType`
- `hasRuntimeErrors`
- `findings[]` with:
  - category
  - severity
  - title / description
  - file / line / column
  - code snippet
  - recommendation

## Programmatic API (Analyzer)

```ts
import { BackendCodeReviewAnalyzer } from './src/analyzer';

const analyzer = new BackendCodeReviewAnalyzer();
const report = analyzer.analyze('./src');

// Findings
console.log(report.totalFindings);

// POCs collected from detectors that generate them
const pocs = analyzer.getPocs();

// Export POC markdown files
analyzer.exportPocsAsMarkdown('./pocs');

// Export one consolidated POC report
analyzer.generateComprehensivePocReport('./pocs/comprehensive-report.md', 'My Service');
```

Generated POC export directories such as `./pocs` are intended as local artifacts and are ignored by the repository by default.

### Phase 1 POC generation

Phase 1 POCs are generated from the analyzer API for detectors that already produce exploit-ready artifacts:

- **Authentication**: hardcoded secret / credential abuse
- **Validation**: injection-style findings such as raw SQL construction from attacker input
- **Mass Assignment**: role-escalation and prototype-pollution style findings

The generated POCs are designed for validation and reporting, not automated exploitation. Each POC can include:

- exploit steps
- reusable payload examples
- code-flow visualization
- business and technical impact
- remediation text and fixed-code examples

Typical Phase 1 export flow:

```ts
const analyzer = new BackendCodeReviewAnalyzer();
analyzer.analyze('./src');

// Individual markdown POCs for supported Phase 1 findings
analyzer.exportPocsAsMarkdown('./pocs');

// One consolidated report for sharing with engineers or security reviewers
analyzer.generateComprehensivePocReport('./pocs/comprehensive-report.md', 'My Service');
```

Comprehensive POC markdown reports now automatically:

- synthesize confirmed exploit chains when multiple compatible POCs exist
- summarize payload reliability and recommended first payloads
- generate prioritized remediation tasks that explicitly break high-impact exploit paths

For Phase 1 usage, this mainly helps turn authentication, validation, and mass-assignment findings into one exploit-oriented review package. For example, the comprehensive report can connect exposed credentials or privilege-escalation primitives to higher-impact data-access narratives when compatible POCs exist.

## Security methodology used

The scanner follows a practical static-analysis workflow:

1. **Attack-surface discovery**: routes, handlers, trust boundaries
2. **Source/sink tracing**: user input to sensitive operations
3. **Missing-control checks**: authz, validation, ownership, locking, crypto hygiene
4. **Exploitability scoring**: severity + contextual signal, with exploit-focused output by default
5. **Fix guidance**: remediation text and code-level recommendations

It is tuned to suppress governance-only hygiene checks in the default report so CI and review flows stay centered on vulnerabilities that are realistically exploitable or chainable in backend services.

## Development

```bash
npm run build
npm test -- --runInBand
```

Current baseline in this repo:

- Build passes
- Tests pass (currently 79/79)

## Repository structure

```text
src/
  analyzer.ts
  index.ts
  reporter.ts
  detectors/
  parser/
  poc/
  rules/
  utils/
tests/
dist/
```

## Known limitations

- Static analysis only (no runtime instrumentation)
- No inter-service runtime traffic correlation
- `--include-heuristics` widens the report to include lower-confidence findings that are excluded from the default exploit-focused view
- Cross-file semantic depth is intentionally lightweight for speed

## License

ISC
