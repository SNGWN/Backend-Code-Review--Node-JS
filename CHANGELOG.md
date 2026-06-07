# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — 2026-06-07

### Added — Framework-architecture awareness
- Taint now seeds from backend ingress points beyond `req.*`: NestJS / type-graphql parameter
  decorators (`@Body()`, `@Param()`, `@Query()`, `@Headers()`, `@Args()`, …), message-queue /
  event-stream consumer callback payloads (`.consume()`, `.on()`, `eachMessage`, `.subscribe()`),
  and Apollo-style GraphQL resolver `args`. Lets data flow be tracked controller → service →
  repository and through consumers.
- One-way transforms (hash/HMAC/encrypt/sign/random derivation) no longer propagate injection
  taint to their output, in both the TaintTracker and the validation detector's taint map.

### Added — Confidence model (`CONFIRMED` / `FIRM` / `TENTATIVE`)
- Every finding now carries a `confidence` (and uncertain ones a `verify` hint). Surfaced in JSON,
  text, and SARIF, with a `findingsByConfidence` summary. Lets the scanner *report* lower-certainty
  findings for the user to triage instead of silently dropping them. Taint-confirmed sinks read as
  CONFIRMED; heuristic rules as TENTATIVE.

### Added — New rules
- `BCR-JWT-009` JWT signed without expiration (TENTATIVE — intent-dependent).
- `BCR-CRYPTO-006` Timing-unsafe secret/signature comparison (`===` on HMAC/signature → webhook
  signature bypass).
- (round 1) `BCR-VAL-013` NoSQL, `BCR-VAL-014` SSTI, `BCR-VAL-015` XXE, `BCR-MISC-005` reflected
  CORS, `BCR-KEY-008` env-fallback secret, `BCR-MA-007` prototype pollution.

### Fixed — Detection accuracy (round 2)
- BOLA detector generalised beyond three hardcoded id names to any client-supplied id
  (`userId`/`_id` → FIRM, ambiguous all-lowercase → TENTATIVE); lookup-context verbs word-bounded.
- Unverified-token (`BCR-AUTH-001`) now checks the enclosing function scope (not just the parent
  node), requires the token to be request-derived, and no longer treats `jwt.decode()`/`check` as
  verification.
- `isTainted` no longer resolves property-name positions (object keys, `.prop` names) as variable
  references — fixed a class of validator/false-positive collisions.
- Fingerprint now includes the line number so two distinct findings sharing a rule + code snippet
  no longer collapse to one fingerprint (which let a baseline entry suppress an unrelated finding).
  NOTE: this invalidates existing baselines — re-run `--update-baseline` once.
- Baseline matching re-validates ruleId + file before suppressing (guards against truncated-hash
  collisions / hand-edited baselines).
- SSRF recognises `ky`/`needle`/`phin` and axios/got instance receivers (client/api/agent/…).
- SARIF: omit dangling `ruleIndex` for legacy/deprecated ids; non-empty `partialFingerprints`
  fallback so distinct findings don't collapse into one GitHub alert.

### Fixed — Security / robustness (round 2)
- ReDoS in the email log rule removed (non-overlapping bounded form).
- POC markdown escapes embedded scanned source (dynamic code-fence length) and HTML-escapes
  finding-derived values in raw HTML tables — closes a markdown/HTML/code-fence breakout vector.
- Kibana: container filter matches both `field` and `field.keyword` (was zero-hits on keyword-only
  mappings); `_source` projection and HTTP response body are size-capped; numeric epoch timestamps
  coerced; `_id`/timestamp URL-encoded in the Discover deep-link.
- Log-review caps per-line length before running the rule set (defence-in-depth against any
  super-linear regex over attacker-controlled lines).

### Added — Self-contained offline release (runs on Windows with zero `npm install`)
- `npm run bundle` (esbuild) produces a single `release/code-review.js` that inlines the
  TypeScript compiler, yargs, fast-glob and ignore. `npm run package:release` wraps it into
  `release/backend-code-review-v<version>.zip` with Windows (`.cmd`) and POSIX launchers.
- `.github/workflows/release.yml` — builds, tests, smoke-tests the bundle with **no
  node_modules**, and attaches the ZIP to a tagged GitHub Release.
- Bundle shims `import.meta.url` (for yargs' ESM shim) and injects the version via
  `__BCR_VERSION__` so `--version` works without a co-located package.json.

### Added — New exploitable-class detectors
- `BCR-VAL-013` NoSQL injection (operator objects, `$where` server-side JavaScript).
- `BCR-VAL-014` Server-Side Template Injection (handlebars/pug/ejs/nunjucks/lodash compile).
- `BCR-VAL-015` XML External Entity (XXE) expansion enabled.
- `BCR-MISC-005` Reflected-origin CORS with credentials (callback + raw-header forms).
- `BCR-KEY-008` Hardcoded secret as `process.env.X || 'literal'` fallback.
- `BCR-MA-007` Prototype pollution via dynamic user-controlled key / recursive merge.

### Added — In-file inter-procedural taint
- `TaintTracker` now builds per-function taint summaries (returns-untrusted / returns-param)
  and propagates taint across calls to local helper functions — "tainted value flowing through
  functions". SQL-injection detection now fires when the query string is built in a separate
  variable and passed as a bare identifier to `.query()`.

### Fixed — Packaging & cross-platform
- `typescript` moved from devDependencies to dependencies (it is a runtime import; a production
  install previously crashed on first scan).
- `yargs` pinned to the last CommonJS line (`^17.7.2`); yargs 18 is ESM-only and threw
  `ERR_REQUIRE_ESM` from the CJS `dist` on Node 18/20.
- Inline `// bcr-disable-line` suppressions now work on Windows (per-file map keys are
  canonicalised through `path.resolve` on both store and lookup).
- `--output` to a non-existent directory creates it for json/text (previously SARIF-only);
  `--max-hits` guards against `NaN` silently zeroing the scan.

### Fixed — Detection accuracy
- Taint source model tightened: dropped bare `payload`/`userdata` substrings and browser-only
  `window.`/`document.`; added gRPC `call.request` and raw-header sources.
- `getEnclosingScopeText` returns the enclosing **function** (not the innermost call) and strips
  comments, so a `// TODO: check req.user...` comment is no longer counted as a real control.
- Lexical-scope shadowing resolution in the taint tracker actually works now (previous version
  was dead code that always fell back to the first declaration).
- `BCR-CRYPTO-001` now catches `crypto.createHash('md5')` / `createHmac('sha1', …)` (previously
  only bare `md5()`/`sha1()` helpers); `BCR-VAL-001` covers TypeORM/Knex `whereRaw`/`*Raw` sinks.

### Fixed — Log / search subsystem
- Removed the `_id` sort tiebreaker that returns HTTP 400 on default ES ≥ 7.6 (fielddata on
  `_id` disabled); pagination now sorts on the timestamp with client-side `_id` dedup.
- Free-text `query_string` no longer fans out across `fields: ['*']`; added
  `allow_leading_wildcard: false` and a determinized-states cap.
- Search-mode excerpts redact all detected secrets even when the query matched a structured
  field, and never echo the raw stringified `_source`.

### Added — Cross-layer coverage (round 3)
- IDOR detection now follows the **service / repository layer**: a controller that delegates to
  `accountService.getAccount(req.params.id)` (or `*Repository`/`*Dao`/`*Store`/`*Manager`/…) with a
  client-supplied id and **no** ownership/tenant argument is reported (`BCR-AC-005`, TENTATIVE +
  `verify`). Suppressed when an owner/tenant id is passed alongside, or an ownership check is visible
  in scope — the guard may legitimately live inside the service, so the user confirms.
- Business-logic **TOCTOU across statements** (`BCR-BL-003`): the check (a balance/stock read or
  comparison) and the act (a non-atomic debit/decrement) no longer have to sit in the same `if` —
  a guard followed by a sibling mutation of the same resource is now flagged (TENTATIVE), skipped
  when the function shows transaction / lock / atomic-update markers (incl. `tx`/`trx`/queryRunner
  transaction-callback handles).

### Fixed — Cross-file & detection correctness (round 3)
- Re-export resolution now mirrors ES-module semantics: a module's **own** local definition shadows
  anything pulled in by `export *`. Previously a file that both defined `export function getId()`
  and had `export * from './other'` mis-resolved `getId` to `./other`, dropping the real local
  taint summary.
- Baseline matching is **case-insensitive on ruleId**, so a hand-edited baseline with `bcr-val-001`
  still suppresses a `BCR-VAL-001` finding.

### Fixed — Log / search correctness (round 3)
- Free-text search reports the ES **matched-total** (`track_total_hits`) — `matchedTotal` /
  `matchedTotalRelation` — distinct from the returned-count `totalHits`, so a capped result reads
  "showing N of M matched" instead of mislabeling the page size as the total.
- Log findings keep each excerpt and reported column **inside one coherent field**: matches in the
  appended structured `_source` projection are labeled `[_source]` and reported at a field-relative
  column, never at an offset that doesn't exist in Kibana's `message` field.

### Fixed — CLI polish (round 3)
- Default output filenames include the pid + a random suffix (not just `Date.now()`), so
  same-millisecond runs can't clobber each other's report.
- `--update-baseline` without `--baseline` co-locates the baseline with the scanned path for code
  scans (logs/search still default to cwd); the resolved absolute path is logged.
- stdout/stderr are drained before `process.exit`, so `--list-rules | jq` (and any piped output)
  can't be truncated mid-write.
- SARIF `artifactLocation.uri` emits a valid `file://` URI when a finding's file is on a different
  Windows drive than the cwd (unrelativizable), instead of a drive-letter pseudo-URI.

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
