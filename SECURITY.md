# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in this scanner, please
report it privately. Do **not** open a public GitHub issue.

Send the report to the project maintainer with:

- A description of the vulnerability
- Steps to reproduce (or a proof of concept)
- The version / commit SHA being scanned
- Any logs or output that demonstrate the issue (with secrets redacted)

We aim to acknowledge reports within 3 business days.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Active    |
| < 1.0   | None      |

## Scope

In scope:

- The CLI binary (`dist/index.js`) and the published library API
- The Kibana / Elasticsearch client (`src/logs/kibanaClient.ts`)
- Rules in `src/rules/registry.ts` and `src/logs/logRules.ts`
- SARIF, JSON, and text reporters

Out of scope:

- Test fixtures under `tests/fixtures/` — these are intentionally vulnerable
- Third-party dependencies — please report upstream

## Sensitive Data Handling

This tool is designed to **detect** secrets and PII in source code and logs. It
must not **leak** them in its own output. The redaction guarantee is enforced by
`tests/logRedactionGuarantee.test.ts` — every rule's matched value is masked in
finding excerpts, descriptions, and SARIF output. If a regression in that
contract is found, please report under the process above.
