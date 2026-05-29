# Compliance Mapping

This document cross-references every rule the scanner emits against the regulations
relevant to a UAE-licensed bank: **PCI-DSS v4.0**, **CBUAE Consumer Protection
Standards**, and **UAE Personal Data Protection Law (PDPL, Federal Decree-Law No. 45
of 2021)**. Each rule also carries CWE references in SARIF output.

## Log-review rules (mode=logs)

| Rule ID | What it detects | PCI-DSS | UAE PDPL | CWE |
| --- | --- | --- | --- | --- |
| LOG-PCI-001 | PAN (Luhn + BIN brand) in log | Req 3.3, 3.4, 3.5.1 | — | CWE-532, CWE-359 |
| LOG-PCI-002 | CVV/CVC in log | Req 3.2 | — | CWE-532 |
| LOG-PCI-003 | Track 1/2 magnetic stripe in log | Req 3.2.1 | — | CWE-532 |
| LOG-PII-001 | UAE Emirates ID in log | — | Art. 24 (sensitive personal data) | CWE-359 |
| LOG-PII-002 | IBAN (mod-97) in log | — | Art. 6 (lawful processing), CBUAE CPS | CWE-359 |
| LOG-PII-003 | Email (heuristic) | — | Art. 6, Art. 9 | CWE-359 |
| LOG-PII-004 | UAE phone number | — | Art. 6, CBUAE CPS § B.2 | CWE-359 |
| LOG-PII-005 | Passport number (heuristic) | — | Art. 24 | CWE-359 |
| LOG-SEC-001 | Plaintext password / env-var disclosure | Req 8.2, 8.6 | Art. 21 (security measures) | CWE-532, CWE-256 |
| LOG-SEC-002 | Bearer / JWT in log | Req 8.2 | Art. 21 | CWE-532 |
| LOG-SEC-003 | Service API key in log | Req 8.2, 6.3 | Art. 21 | CWE-532, CWE-798 |
| LOG-SEC-004 | PEM private key in log | Req 3.5, 8.2 | Art. 21 | CWE-532, CWE-798 |
| LOG-OPS-001 | DB connection string with credentials | Req 8.2 | Art. 21 | CWE-209, CWE-532 |
| LOG-OPS-002 | Stack trace with sensitive path | — | — | CWE-209 |

## Code-review rules (mode=code)

Selected high-impact mappings. Full catalog: `node dist/index.js --list-rules`.

| Rule ID | What it detects | PCI-DSS | UAE PDPL | CWE |
| --- | --- | --- | --- | --- |
| BCR-AUTH-002 / BCR-AUTH-004 | Hardcoded secret / token | Req 8.2 | Art. 21 | CWE-798, CWE-259 |
| BCR-JWT-001 | JWT signature not verified | Req 8.3 | Art. 21 | CWE-345, CWE-347 |
| BCR-JWT-002 | `alg: none` allowed | Req 6.2 | Art. 21 | CWE-327, CWE-347 |
| BCR-JWT-005 | Weak HMAC secret | Req 3.6, 8.2 | Art. 21 | CWE-326, CWE-521 |
| BCR-VAL-001 | SQL injection sink with tainted input | Req 6.2.4 | Art. 21 | CWE-89 |
| BCR-VAL-005 | Unsafe JSON.parse on user input | Req 6.2.4 | — | CWE-502, CWE-1321 |
| BCR-VAL-011 | SQL injection via tagged-template | Req 6.2.4 | — | CWE-89 |
| BCR-VAL-012 | Insecure base64 deserialization | Req 6.2.4 | — | CWE-502 |
| BCR-SSRF-001 | Outbound request with user-controlled URL | Req 6.2.4 | Art. 21 | CWE-918 |
| BCR-REDIRECT-001 | Open redirect | — | Art. 21 | CWE-601 |
| BCR-PT-001 | Path traversal in fs sink | Req 6.2.4 | Art. 21 | CWE-22, CWE-23 |
| BCR-MA-001, BCR-MA-006 | Mass assignment | Req 6.2.4 | — | CWE-915 |
| BCR-AC-002 / BCR-AC-005 | BOLA / IDOR | Req 7.1 | Art. 6 | CWE-639, CWE-284 |
| BCR-MISC-001 | CORS `origin: '*'` | Req 6.4.4 | — | CWE-942, CWE-346 |
| BCR-MISC-004 | Weak bcrypt cost factor | Req 8.6.2 | Art. 21 | CWE-916, CWE-326 |
| BCR-CRYPTO-002 | `Math.random()` for tokens | Req 3.6.3 | Art. 21 | CWE-338, CWE-330 |
| BCR-CRYPTO-005 | Deprecated `createCipher` (no IV) | Req 3.5, 3.6 | Art. 21 | CWE-327, CWE-329 |
| BCR-KEY-005 | Service API key in logs | Req 8.2, 10.6.1 | Art. 21 | CWE-532, CWE-798 |
| BCR-LOG-001 | Sensitive data in logs (code path) | Req 10.6.1 | Art. 21 | CWE-532, CWE-200 |

## How auditors use this

1. Run the scanner against both source (`--mode code`) and 15-day production logs
   (`--mode logs --days 15`), output SARIF to a shared evidence store.
2. For each finding, cross-reference the rule ID against this table to obtain the
   PCI-DSS / PDPL clause it impacts.
3. Use the `partialFingerprints` field for stable cross-run tracking of remediation.
4. The redaction guarantee (`tests/logRedactionGuarantee.test.ts`) confirms that the
   scanner's OWN output does not constitute a PCI-DSS reportable event.

## References

- PCI-DSS v4.0 — https://www.pcisecuritystandards.org/document_library/
- UAE PDPL Federal Decree-Law 45/2021 — https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws
- CBUAE Consumer Protection Standards — https://www.centralbank.ae/
- CWE — https://cwe.mitre.org/
- OWASP Top 10 (2021) — https://owasp.org/Top10/
