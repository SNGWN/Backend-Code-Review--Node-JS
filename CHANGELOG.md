# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
