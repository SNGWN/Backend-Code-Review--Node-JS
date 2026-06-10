# Backend Code Review Scanner

Two-mode security scanner for Node.js / TypeScript backends. Built for AppSec engineers
running in CI:

- **`--mode code`** (default): static SAST over local source. SARIF / baseline / severity
  thresholds / 60+ rules with CWE + OWASP mapping.
- **`--mode logs`**: Kibana / Elasticsearch log review. Scans the last N days of a
  container's logs for PCI-DSS (PAN with Luhn, CVV, track data), UAE PDPL / PII
  (Emirates ID, IBAN with mod-97, phone, passport), and secrets in logs (passwords,
  Bearer / JWT, service API keys, private keys, DB connection strings).

Both modes emit the same Finding shape — same SARIF output, same baseline format, same
fail-on / min-severity gating. AppSec teams ingest both code and log findings through one
pipeline.

A third mode — **`--mode search`** — runs a free-text Elasticsearch query across the
entire cluster (or a specific container) for ad-hoc investigation. Useful for incident
response: "is this customer ID anywhere in the last 7 days?" Output is the same SARIF /
JSON shape; the matched term is redacted in the output so the artifact itself doesn't
leak the value you searched for.

## What it produces

- **Findings** with stable `ruleId`, CWE list, OWASP category, content-addressed fingerprint
- **JSON** report (default), **text** summary, or **SARIF 2.1.0** for GitHub code scanning
  / DefectDojo / SonarQube ingest
- **POC artifacts** (markdown) for supported exploit-ready finding classes

## Install

### From source (development)

```bash
npm install
npm run build      # produces dist/ (tsc)
node dist/index.js --path ./src
```

### Self-contained release (offline / Windows, no `npm install`)

Build a single bundled file that inlines the TypeScript compiler and all dependencies — it runs
anywhere Node.js ≥ 18 is installed, with **zero** `npm install` on the target machine:

```bash
npm run package:release      # -> release/backend-code-review-v<version>.zip
#   or
npm run bundle               # -> release/code-review.js (just the bundle)
```

Unzip on the target and run directly:

```bash
# Windows (cmd / PowerShell)
code-review.cmd --path C:\path\to\service\src --format sarif --output report.sarif
node code-review.js --list-rules

# macOS / Linux
./code-review --path ./src --include-heuristics
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the air-gapped install procedure.

## Quick start

### Code review (default mode)

```bash
# Default JSON report
node dist/index.js --path ./src --output report.json

# SARIF for GitHub code scanning
node dist/index.js --path ./src --format sarif --output report.sarif

# Show only critical findings; CI fails on the same threshold
node dist/index.js --path ./src --min-severity CRITICAL --fail-on CRITICAL

# Establish a baseline of currently-known findings; future scans suppress them
node dist/index.js --update-baseline --baseline .security-baseline.json --path ./src

# Subsequent scans drop everything in the baseline
node dist/index.js --baseline .security-baseline.json --path ./src --format sarif --output report.sarif
```

### Log review (Kibana / Elasticsearch)

```bash
# Credentials NEVER go on the command line. Use env vars or --password-stdin.
export KIBANA_URL=https://kibana.bank.ae:5601
export KIBANA_USERNAME=appsec-reader
export CONTAINER_NAME=payments-svc

# Recommended: read password from stdin (no bash history leak)
echo -n "$KIBANA_PASSWORD" | node dist/index.js \
  --mode logs \
  --password-stdin \
  --days 15 \
  --log-index "filebeat-*" \
  --format sarif --output payments-svc-15d.sarif

# Alternative: KIBANA_PASSWORD env var
KIBANA_PASSWORD=... node dist/index.js --mode logs --format json --output report.json

# Direct ES transport (when Kibana proxy is unavailable)
node dist/index.js --mode logs --transport direct --kibana-url https://es.bank.ae:9200 ...

# Tighten the window for a quick smoke check
node dist/index.js --mode logs --days 1 --max-hits 1000 --format text --output report.txt
```

Log-review inputs (flag → env var fallback):

| Flag | Env var | Required | Notes |
| --- | --- | --- | --- |
| `--kibana-url` / `--elasticsearch-url` | `KIBANA_URL` / `ELASTICSEARCH_URL` | yes | Base URL of Kibana or ES |
| `--username` `-u` | `KIBANA_USERNAME` | yes | |
| (stdin) `--password-stdin` | `KIBANA_PASSWORD` | yes | Plaintext CLI is **not** supported |
| `--container` | `CONTAINER_NAME` | yes | Exact match |
| `--container-field` | `CONTAINER_FIELD` | no | Default `kubernetes.container.name` |
| `--log-index` | `LOG_INDEX` | no | Default `filebeat-*` |
| `--days` | `LOG_REVIEW_DAYS` | no | Default 15, max 365 |
| `--transport` | — | no | `kibana-proxy` (default) or `direct` |
| `--max-hits` | — | no | Safety cap (default 50000) |
| `--insecure` | — | no | Skip TLS verification (private CA only) |
| `--proxy` | `HTTPS_PROXY` / `HTTP_PROXY` | no | Forward proxy; `NO_PROXY` honored |

#### Restricted-network access (proxy, redirects, private CAs)

Bank and enterprise networks rarely expose Kibana directly. The client handles the
three common obstacles without extra tooling:

- **Forward proxy** — pass `--proxy http://proxy.bank.ae:8080` (or rely on the standard
  `HTTPS_PROXY` / `HTTP_PROXY` env vars; `NO_PROXY` host suffixes are honored for
  env-derived proxies). HTTPS targets are tunneled with CONNECT; proxy credentials go
  in the URL userinfo (`http://user:pass@proxy:8080`) and are sent as
  `Proxy-Authorization`, never logged.
- **Redirects** — 301/302/303/307/308 chains (http→https upgrades, SSO gateways, host
  canonicalization) are followed up to 5 hops. The `Authorization` header is forwarded
  **only on same-origin hops** — a redirect to a different host never receives the
  Kibana credential. Loops fail fast with the (credential-scrubbed) chain in the error.
- **Private CAs / unverified certificates** — `--insecure` disables target-certificate
  validation (it applies identically through a proxy tunnel). Use it only for trusted
  private-CA clusters; the scanner warns loudly when active.

Log rules ship with PCI-DSS / UAE PDPL / OWASP-A09 mapping. The `--list-rules` output
shows the full catalog including `LOG-*` rules with CWE references (CWE-532, CWE-359,
CWE-256, etc.).

#### UAE compliance specifics

- **Emirates ID** (`LOG-PII-001`) is validated in two tiers: shape + birth-year sanity
  + **Luhn check digit** → HIGH (near-certain real EID); a shape match whose checksum
  fails is still reported (recall matters for national IDs) but demoted to MEDIUM with
  explicit verify wording. Findings reference UAE PDPL Art. 4/5/24 and CBUAE Consumer
  Protection Standards.
- **UAE IBAN** (`LOG-PII-002`) — full ISO 13616 mod-97 validation, AE and foreign IBANs.
- **UAE phone numbers** (`LOG-PII-004`) — `+971` and `05X` local formats.
- Excerpts in findings are **always redacted** — the report itself can never become the
  PCI/PDPL leak.

### Free-text search (`--mode search`)

For investigations — "is this customer ID anywhere in the last 7 days?". The query is
sent as an Elasticsearch `query_string` (so the user gets full Lucene syntax: boolean
operators, field qualifiers, wildcards).

```bash
# Across all indices the user can read (no container scope):
KIBANA_PASSWORD=… code-review --mode search \
  --kibana-url https://kibana.bank.ae:5601 \
  --username appsec-reader \
  --query 'alice@bank.ae OR "Emirates ID 784-1990-1234567-8"' \
  --days 7 --max-hits 200

# Scoped to a specific container:
code-review --mode search --container payments-svc \
  --query 'order_id:ORD-12345 AND status:failed' \
  --days 30
```

Search inputs:

| Flag | Env var | Required | Notes |
| --- | --- | --- | --- |
| `--kibana-url` | `KIBANA_URL` | yes | Base URL |
| `--username` `-u` | `KIBANA_USERNAME` | yes | (or `KIBANA_API_KEY_ID` + `KIBANA_API_KEY`) |
| stdin or env | `KIBANA_PASSWORD` | yes | Plaintext flag not supported |
| `--query` `-q` | — | yes | ES `query_string` syntax |
| `--container` | `CONTAINER_NAME` | no | Omit to search the entire cluster |
| `--days` | `LOG_REVIEW_DAYS` | no | Default 7 for search |
| `--max-hits` | — | no | Default 200 |
| `--log-index` | `LOG_INDEX` | no | Default `*` (search-mode default) |
| `--proxy` | `HTTPS_PROXY` / `HTTP_PROXY` | no | Forward proxy; `NO_PROXY` honored |

The matched query term is **redacted in the output** — reviewers can locate WHERE the
term appears without the artifact itself becoming a leak.

Search mode always exits `0` when Kibana is reachable, regardless of hit count — it's
an investigation tool, not a CI gate.

## CLI

| Option | Description | Default |
| --- | --- | --- |
| `--path` `-p` | File or directory to analyze | `.` |
| `--output` `-o` | Report file path | `code-review-<timestamp>.<ext>` |
| `--format` `-f` | `json`, `text`, or `sarif` | `json` |
| `--include-heuristics` `-a` | Include lower-confidence (heuristic) rules | `false` |
| `--min-severity` | Drop findings below `CRITICAL|HIGH|MEDIUM|LOW|INFO` | severity-thresh `HIGH` by default, `LOW` with `--include-heuristics` |
| `--fail-on` | Exit non-zero only when a finding of at least this severity remains | `HIGH` |
| `--baseline <path>` | Suppress findings whose fingerprint is in this baseline | unset |
| `--update-baseline` | Write current findings to `--baseline` path and exit `0` | `false` |
| `--disable-rule <id>` | Drop findings for the named rule (repeatable; comma-separated) | unset |
| `--show-suppressed` | Include suppressed findings in SARIF output for reviewer visibility | `false` |
| `--list-rules` | Print the rule catalog (id, severity, CWE, OWASP) and exit | `false` |
| `--quiet` / `--verbose` | Console verbosity | both `false` |
| `--log-format` | Console log format (`text` or `json`) | `text` |
| `--fail-on-runtime-errors` | Non-zero exit on parse/detector runtime errors | `true` |

All console output goes to stderr so stdout is safe to pipe through `jq` etc.

## Output: report shape

```jsonc
{
  "timestamp": "2026-05-29T...",
  "filesAnalyzed": 12,
  "totalFindings": 4,
  "findingsByCategory": { "AUTHENTICATION": 2, "VALIDATION": 1, "..." },
  "findingsBySeverity": { "CRITICAL": 2, "HIGH": 2, "..." },
  "findings": [
    {
      "ruleId": "BCR-AUTH-002",
      "category": "AUTHENTICATION",
      "severity": "CRITICAL",
      "title": "Hardcoded Secret/Token",
      "file": "src/auth/keys.ts",
      "line": 12,
      "column": 7,
      "code": "const JWT_SECRET = 'k7Hf91p2QvX8r4Lc2NaB3Tg5Y6Wm0Eu9'",
      "recommendation": "...",
      "fingerprint": "a1b2c3d4e5f60718",
      "cwe": ["CWE-798", "CWE-259"],
      "owasp": "A07:2021 - Identification and Authentication Failures"
    }
  ],
  "runtimeIssues": [],
  "hasRuntimeErrors": false
}
```

## SARIF

`--format sarif` emits a SARIF 2.1.0 document with:

- `tool.driver.rules[]` — full rule catalog from the registry (stable IDs)
- `tool.driver.taxa[]` — CWE and OWASP taxonomies cross-referenced from each result
- `results[].partialFingerprints["primaryLocationLineHash/v1"]` — content-addressed
  fingerprint matching the baseline format. GitHub code scanning uses this for dedup.
- `results[].suppressions[]` when `--show-suppressed` is enabled
- `properties["security-severity"]` numeric (matches GitHub's severity column)

This is the canonical format to consume from CI. Upload via
[`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action) or your
DefectDojo/Sonar SARIF ingest.

## Suppression

Two complementary mechanisms, both keyed on the finding's stable fingerprint.

### Baseline (out-of-source)

```bash
# Snapshot current findings — commit this file
node dist/index.js --update-baseline --baseline .security-baseline.json --path ./src

# Subsequent runs ignore anything in the baseline
node dist/index.js --baseline .security-baseline.json --path ./src
```

The baseline format (v1) persists only fingerprints — no source snippets — so it is
safe to commit even when source contains real secrets:

```json
{
  "version": 1,
  "generatedAt": "2026-05-29T00:00:00.000Z",
  "entries": [
    { "fingerprint": "a1b2c3d4e5f60718", "ruleId": "BCR-AUTH-002", "file": "src/auth/keys.ts" }
  ]
}
```

Fingerprints are computed from `ruleId + normalized-path + normalized-code` (whitespace
collapsed), so adding/removing unrelated lines above the finding does not invalidate
the baseline. This is the property AppSec teams need from a baseline: a triage decision
shouldn't churn on every refactor.

### Inline (in-source)

```ts
// bcr-disable-next-line BCR-AUTH-004 -- triaged 2026-05-29, key rotates monthly
const JWT_SECRET = process.env.JWT_SECRET ?? FALLBACK;

const X = 'value'; // bcr-disable-line BCR-AUTH-002 -- intentional test fixture
```

- Rule IDs are case-insensitive
- Multiple rules: `// bcr-disable-next-line BCR-VAL-001,BCR-VAL-005 -- both apply`
- All rules on the line: `// bcr-disable-line * -- reason`
- The `-- reason` is required-in-spirit (surfaced in SARIF `suppressions[].justification`)
  and strongly encouraged for audit

## Rule catalog

```bash
node dist/index.js --list-rules
```

Every rule has a stable ID like `BCR-AUTH-002`. The ID is the contract: never renumbered,
never renamed; deprecated rules stay listed with `deprecated: true` to preserve baseline
stability.

Rules are grouped into two confidence tiers:

- **Default-on** rules emit by default — these are high-signal, low-FP patterns.
- **Heuristic** rules (`heuristic: true`) emit only with `--include-heuristics`. They
  capture broader patterns but have known false-positive shapes.

## False-positive philosophy

This scanner is tuned for **AppSec engineer review noise tolerance**, not academic
recall. The defaults prefer false negatives over false positives. To widen recall:

```bash
node dist/index.js --path ./src --include-heuristics --min-severity LOW
```

The `tests/fpRegression.test.ts` suite pins the known FP shapes that the default
configuration must never emit. Adding a detector tweak that regresses any of these
patterns fails the build.

## Coverage

The default ruleset emits findings for:

- **Authentication / JWT** — hardcoded secrets, missing signature verification,
  algorithm-confusion (`alg:none`, RS256/HS256 key confusion), weak HMAC secret,
  expiration-disabled, unverified token usage
- **Injection** — SQL via interpolated strings (anchored to DB-shaped receivers),
  command execution (`exec`/`spawn` plus alias resolution), `eval`/Function-constructor,
  fs-sink path injection, **tagged-template SQL** (`` sql`SELECT ... ${tainted}` ``),
  **prototype pollution** via JSON.parse / spread / Object.assign
- **SSRF / Open Redirect** — outbound HTTP with user-controlled URL,
  `res.redirect(req.X)` without allowlist
- **Path Traversal** — filesystem sinks with user-controlled path, suppressed when the
  enclosing scope shows a `path.resolve(BASE_DIR, …)` + `.startsWith(BASE_DIR)`
  containment idiom
- **Access Control** — missing auth/authz on sensitive endpoints (tightened from the
  audit's overbroad version: requires both a credentialed-action handler AND mutation
  evidence), BOLA / IDOR / horizontal escalation, privilege escalation (admin
  functions touching request data without role check)
- **Mass Assignment / Object Pollution** — `Object.assign(target, req.body)`, direct
  spread of unvalidated input, prototype/`__proto__`/constructor assignment
- **Rate Limiting** — header-bypass, weak limits, distributed (in-memory store)
  bypass, missing limit on credential endpoints
- **Crypto Weakness** — `md5`/`sha1` on passwords, `Math.random()` for tokens and
  **identifiers/session ids/reset codes/OTPs/nonces** (new), hardcoded keys
- **Secret Exposure** — service-specific patterns (Stripe, AWS, GitHub, Firebase,
  SendGrid, Twilio), generic-name + entropy heuristic with HTTP-header-shape
  exclusion, DB connection strings
- **Logging** — secrets in log payloads (excluding plain string-literal labels),
  log-injection via user input in templates
- **Insecure Transport / TLS** — `rejectUnauthorized: false` on any HTTPS/TLS options
  object (https.Agent / tls.connect / axios / got / node-fetch agents), and the
  process-global `NODE_TLS_REJECT_UNAUTHORIZED = "0"` kill switch (both CWE-295 MITM)
- **Cookie Security** — session/auth cookies set without `httpOnly` (XSS session theft),
  `secure` (cleartext transmission), or `sameSite` (CSRF), across `res.cookie()`,
  `express-session`, and `cookie-session`, with library-default-aware gating
- **Cache Poisoning, Queue, Event Stream** — see rule catalog
- **Data Exposure** — sensitive fields in response shapes

The new techniques the architecture adds:

- **Scope-aware taint** with validator-aware detainting (zod / yup / joi / ajv /
  class-validator / valibot / io-ts / typebox), recognising both bare functions and
  schema `.parse()` / `.safeParse()` shapes
- **Import-alias resolution** so `import { exec as runShell } from 'child_process'`
  is still caught by command-execution rules even after rename
- **Stable content fingerprints** (`sha256(ruleId + normalized-path + normalized-code)`)
  so baselines and SARIF dedup don't churn on whitespace / line shifts
- **CWE + OWASP taxa** cross-referenced from the SARIF tool driver — drops straight
  into GitHub code scanning's filter UI

## Limitations (honest)

- **Single-file taint.** Cross-file flow is not tracked. A value tainted in `routes.ts`
  and consumed in `db.ts` will not chain. The taint tracker uses scope-aware AST
  identifier resolution within one source file (not the full TypeChecker), which keeps
  setup zero-config but means it cannot follow imports.
- **No symbol-table-level type information.** We do not run the TypeScript checker, so
  rules cannot use type info to disambiguate. This is a deliberate trade — running the
  checker requires per-project `tsconfig.json` discovery and is slow on large
  monorepos. Detectors that would benefit (e.g. ORM-method recognition) instead use
  conservative call-name + receiver patterns. The import-alias resolver handles the
  most common case (renamed dangerous imports) without that infrastructure.
- **Detection is intra-procedural.** Helpers that pass tainted values through are not
  followed across call boundaries within the same file. This reduces recall but
  eliminates a large class of FPs from heuristic propagation.
- **POC layer is detection-coupled.** POC generation is currently driven from a fixed
  set of detector types. Adding a rule does not automatically produce a POC.
- **Zero-FP target is for the default mode.** The `--include-heuristics` mode runs
  broader rules with known FP shapes — surface findings there to widen recall, gate
  them out of CI failure via `--fail-on HIGH`. The FP audit corpus in
  `tests/fixtures/fp-audit/` is the contract: any default-mode finding on a file in
  that directory is a bug.

## Determinism

- Finding `fingerprint` is content-addressed (sha256 of ruleId + normalized path +
  normalized code, truncated to 16 hex)
- Findings are sorted `severity desc → file asc → line asc → ruleId asc` so reports
  diff cleanly across runs
- Console output goes to stderr; SARIF/JSON output is byte-stable for the same input

## Exit codes

- `0` — no findings at or above `--fail-on` severity, no blocking runtime errors
- `1` — failing findings present, OR runtime errors when `--fail-on-runtime-errors` is on

## CI: GitHub Actions example

```yaml
- name: Backend Code Review
  run: |
    node dist/index.js --path ./src --format sarif --output bcr.sarif \
      --baseline .security-baseline.json \
      --min-severity HIGH --fail-on HIGH

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bcr.sarif
```

## Development

```bash
npm run build
npm test -- --runInBand
```

## Documentation

- [`docs/COMPLIANCE-MAPPING.md`](docs/COMPLIANCE-MAPPING.md) — every rule mapped to
  PCI-DSS v4.0 / UAE PDPL / CBUAE CPS clauses, plus CWE references.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — offline-install, CI integration
  recipes for code + log modes, baseline workflow, performance numbers.
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure policy + redaction
  guarantee details.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.

## License

[ISC](LICENSE).
