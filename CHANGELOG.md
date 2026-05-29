# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-05-29

### Added — Cross-file workflow
- `ProjectContext` (`src/utils/projectContext.ts`) — multi-file pre-pass that
  builds an import / re-export graph + per-exported-function summaries.
  Lightweight: no TypeScript Compiler API, no per-project tsconfig discovery.
- `buildReExportList` wired into the resolver — re-exports
  (`export { exec } from 'child_process'`) are now traceable through
  arbitrary-depth alias chains (HOP_LIMIT=16, circular-safe).
- Two-pass analyzer: for directory scans, projectContext is built BEFORE
  per-file detection, then injected into validation + SSRF detectors via
  the factory signature. Single-file scans skip the pre-pass.
- ValidationDetector: `getDangerousSink` falls back to
  `ProjectContext.callResolvesToDangerousBuiltin` (catches re-exported
  exec/spawn/etc.); `referencesTaintedInput` walks for cross-file
  tainted-return helpers and direct-aliased tainted variables.
- SsrfDetector: `getCallSinkName` consults project context first so
  re-exported fs / outbound-HTTP APIs are caught at the call site.
- Default-export + `export default function` source helpers handled
  (closes F5).
- Specific named re-export takes precedence over wildcard (closes a bug
  where `export * from './a'; export { foo } from './b'` resolved `foo`
  to `'./a'`).
- Nested function bodies excluded from outer function's tainted-return
  walk (no longer falsely flags `.map(x => req.body.x)` as tainting the
  outer function).
- Cross-file fixtures + tests (`tests/crossFileWorkflow.test.ts`):
  F1 source helper, F3 re-export, F4 multi-hop alias chain, F5 default-export,
  F6 JS-only project.

### Added — Architecture
- Iterative `ASTVisitor.visit` + `findNodes`. Closes the 4000-depth ternary
  stack-overflow class identified by the architecture audit; same pre-order
  semantics; depth now bounded by heap rather than stack.
- `.js` / `.mjs` / `.cjs` / `.jsx` extension support in `FileHelper`. The
  scanner previously globbed only `.ts` / `.tsx`, making it unusable on
  the dominant JS Express boilerplate shape.
- Removed `tests/fixtures/**/*.js` from `.gitignore` so JS fixtures are
  committable.

### Added — Authentication
- `--bearer-token-stdin` flag + `KIBANA_BEARER_TOKEN` env for SSO
  (Okta / PingFederate / OIDC) bearer-token auth.
- `--api-key-stdin` flag for piping ES API key without writing to env.
- `SIGTERM` handler alongside `SIGINT` in both log-review and search
  modes (k8s / Docker graceful-shutdown).

### Added — Log-rule coverage (+9 rules)
- LOG-SEC-015 — HTTP Basic-auth header `Authorization: Basic <base64>`.
- LOG-SEC-016 — Slack / Discord / MS-Teams incoming-webhook URLs.
- LOG-SEC-017 — GitHub fine-grained PATs (`github_pat_…`), npm tokens
  (`npm_…`), OpenAI keys, Heroku keys.
- LOG-SEC-018 — AWS / GCP / Azure / Cloudflare presigned URLs (signature
  query params).
- LOG-PII-009 — US Social Security Number (area / group / serial sanity).
- LOG-PII-010 (alias) — UK National Insurance Number.
- LOG-PII-011 (alias) — Pakistani CNIC.
- LOG-PII-012 (alias) — Indian Aadhaar (labelled).
- LOG-SEC-019 — PEM private key body without header (label + `MII…`
  base64 body, Shannon entropy ≥ 5.0).

### Added — Output / compliance
- `AnalysisReport.findingsByRule: Record<ruleId, count>` for PCI-DSS
  Req 10 evidence.
- SARIF `runs[0].properties.bcrStatistics` carries the same byRule /
  byCategory / bySeverity histograms for DefectDojo / GitHub Code
  Scanning ingest.
- SARIF log-mode findings preserve `properties.logEvidence` (Kibana URL,
  container, doc id, timestamp) and append the URL to `message.text` so
  reviewers can click through from DefectDojo's findings list.
- PCI-DSS-compliant excerpt masking: PAN-shaped runs use first-6 + last-4
  (`424242******4242`) per Req 3.3 instead of the older 2+2 (`42**********42`).
- Search-mode CLI banner masks the `--query` value so PAN / Emirates-ID
  doesn't leak into stdout / CI capture.
- Multi-container search: `--container payments-svc,onboarding-svc` emits
  an ES `terms` filter, fanning out across services in a single scan.

### Added — Operational hardening
- KibanaClient: specific error messages for HTTP 404
  `index_not_found_exception`, HTTP 401/403, and 200 OK with non-JSON
  body (LB error pages). Body prefix scrubbed for credentials before
  surfacing to the operator.

## [1.1.0] — 2026-05-29

### Added — Expanded log coverage
- **PII**: customer full name (LOG-PII-006), date of birth (LOG-PII-007), physical
  address (LOG-PII-008, heuristic).
- **Account / financial identifiers**: bank account number (LOG-ACCT-001), sort
  code / routing number (LOG-ACCT-002), SWIFT / BIC (LOG-ACCT-003, heuristic).
- **UAE documents**: driving license (LOG-DOC-001), visa / residence permit
  (LOG-DOC-002), TRN (LOG-DOC-003, heuristic), generic national ID (LOG-DOC-004,
  heuristic).
- **Card info expansion**: card expiry (LOG-PCI-005), cardholder name (LOG-PCI-006).
- **Balances**: account balance disclosure (LOG-FIN-001, heuristic).
- **IPs**: public IPv4 in customer context (LOG-NET-001), IPv6 in customer context
  (LOG-NET-002, heuristic), internal RFC-1918 exposure (LOG-NET-003, heuristic).
- **Tokens / OAuth**: client_secret (LOG-SEC-005), client_id (LOG-SEC-006,
  heuristic), refresh_token (LOG-SEC-007), session_token (LOG-SEC-008), CSRF token
  (LOG-SEC-009, heuristic), SSH key (LOG-SEC-010), Azure SAS (LOG-SEC-011), GCP
  service account JSON (LOG-SEC-012), public / API token (LOG-SEC-013), generic
  high-entropy `*_secret=` / `*_key=` / `*_token=` (LOG-SEC-014, heuristic, Shannon
  entropy ≥ 3.6 bits/char gate).

### Added — Free-text search mode (`--mode search`)
- New mode for investigative lookups. Sends user-supplied query as an ES
  `query_string` over the configured index (default `*` in search mode).
- Optional container scope (`--container`) for narrowing; omit for cluster-wide.
- Output: per-hit `(index, doc_id, timestamp, container, kibanaUrl, excerpt)` with
  the matched term redacted in both the report's `query` field and each excerpt —
  the search artifact doesn't itself leak what the user searched for.
- Always exits 0 when Kibana is reachable; search is investigation, not a CI gate.

### Changed
- Log FP audit corpus test pulls heuristic ruleIds from the registry dynamically;
  new heuristic rules are auto-respected without test edits.

## [1.0.0] — 2026-05-29

Initial public release.

### Added — Code-review mode (`--mode code`)
- 75+ rules across AUTHENTICATION, VALIDATION, MASS_ASSIGNMENT, ACCESS_CONTROL,
  RATE_LIMITING, CRYPTO_WEAKNESS, DATA_EXPOSURE, API_KEY_EXPOSURE, SSRF,
  PATH_TRAVERSAL, OPEN_REDIRECT, MISCONFIGURATION, CACHE_POISONING,
  MESSAGE_QUEUE, EVENT_STREAM, LOGGING, BUSINESS_LOGIC.
- Stable rule IDs (`BCR-*`) with CWE + OWASP Top 10 (2021) mapping.
- Scope-aware AST taint tracker with validator-aware detainting
  (zod / joi / yup / ajv / class-validator / valibot / io-ts).
- Import-alias resolver for renamed dangerous imports
  (`import { exec as runShell } from 'child_process'`).
- SARIF 2.1.0 output with `tool.driver.rules[]`, taxonomies (CWE + OWASP),
  `partialFingerprints` for GitHub code-scanning dedup.
- Baseline file (v1) keyed on content-addressed fingerprints — stable across
  whitespace / line shifts.
- Inline suppression: `// bcr-disable-next-line RULE_ID -- reason`.

### Added — Log-review mode (`--mode logs`)
- Kibana / Elasticsearch client with Basic + API-key auth, HTTP keep-alive,
  exponential-backoff retry on transient 5xx / ECONNRESET, configurable timeout.
- 17 log rules across LOG_PCI, LOG_PII, LOG_SECRET, LOG_OPS:
  - **PCI**: PAN with Luhn + BIN-prefix card-brand identification
    (Visa / Mastercard / Amex / Discover / JCB / Diners / UnionPay),
    URL-encoded PAN variant, CVV / CVC labels, Track 1/2 magnetic stripe.
  - **PII**: UAE Emirates ID (year-range sanity), IBAN (mod-97), email,
    UAE phone (+971/05X), passport (labelled).
  - **Secrets**: plaintext password (rejects masked/sentinel), env-var-shaped
    password disclosure (`DB_PASS=`), Bearer/JWT, service API keys
    (AWS / Stripe / GitHub / Firebase / SendGrid / Twilio), AWS STS session
    token, PEM private key, DB connection string with credentials.
  - **Ops**: stack trace with sensitive directory tokens.
- Multi-rule excerpt redaction — co-located sensitive values are masked
  alongside the primary match (PCI-DSS / UAE PDPL invariant).
- Kibana Discover deep-link in every finding's `logEvidence`.
- SIGINT-safe streaming with progress callback every 500 hits.
- Same SARIF / baseline / `--fail-on` / `--disable-rule` semantics as code mode.

### Added — CLI / operations
- `--mode code|logs` (default `code`).
- `--min-severity`, `--fail-on`, `--baseline`, `--update-baseline`,
  `--disable-rule`, `--show-suppressed`, `--list-rules`.
- `--password-stdin` (TTY-detection guard so the tool doesn't hang on a
  missing pipe).
- `KIBANA_PASSWORD` and `KIBANA_API_KEY_ID + KIBANA_API_KEY` env-var auth.
- Yargs strict mode — unknown flags / invalid enum values exit code 2.

### Added — Quality gates
- 197 tests across 23 suites: 14 code-mode FP-audit fixtures (zero default
  findings), log-mode FP-audit corpus (real-world bank log shapes that must
  not fire), HTTP-layer mock-server tests for the Kibana client, redaction
  guarantee that asserts raw sensitive values never appear in output, CLI
  subprocess integration tests, SARIF schema-shape regression.
- Deterministic SARIF output (byte-identical across runs).
- Content-addressed fingerprints stable across whitespace / line shifts.
