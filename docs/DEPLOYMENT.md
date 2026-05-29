# Deployment

## Runtime requirements

- Node.js ≥ 18.0.0. Tested against 18.x, 20.x, and 22.x.
- No native dependencies — pure JavaScript / TypeScript at runtime.
- No outbound network calls in code-review mode (`--mode code`). Log-review mode
  (`--mode logs`) contacts Kibana / Elasticsearch only.

## Offline install (bank-air-gapped environments)

1. On an internet-connected workstation:
   ```bash
   npm install --omit=dev
   npm run build
   npm pack
   ```
   This produces `backend-code-review--node-js-1.0.0.tgz`.
2. Record the SHA-256 of the tarball:
   ```bash
   shasum -a 256 backend-code-review--node-js-1.0.0.tgz
   ```
3. Transfer the tarball over the allowed channel and verify the SHA on the target.
4. Install globally:
   ```bash
   npm install -g ./backend-code-review--node-js-1.0.0.tgz
   ```
5. Verify the binary:
   ```bash
   code-review --version
   code-review --list-rules | jq 'length'
   ```

## CI integration

### Code-review mode (every PR)

```yaml
- name: Code review
  run: |
    code-review --path ./src \
      --format sarif --output bcr-code.sarif \
      --baseline .security-baseline.json \
      --fail-on HIGH

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bcr-code.sarif
    category: backend-code-review
```

### Log-review mode (nightly / weekly cron)

```yaml
- name: Log review
  env:
    KIBANA_URL:      ${{ secrets.KIBANA_URL }}
    KIBANA_USERNAME: ${{ secrets.KIBANA_READER_USER }}
    KIBANA_PASSWORD: ${{ secrets.KIBANA_READER_PASS }}
    CONTAINER_NAME:  payments-svc
  run: |
    code-review --mode logs \
      --days 15 \
      --log-index 'filebeat-*' \
      --format sarif --output bcr-logs-payments-15d.sarif \
      --baseline .security-baseline-logs.json \
      --fail-on CRITICAL
```

If your cluster uses ES API keys instead of Basic:

```yaml
env:
  KIBANA_API_KEY_ID: ${{ secrets.KIBANA_API_KEY_ID }}
  KIBANA_API_KEY:    ${{ secrets.KIBANA_API_KEY }}
```

## Permissions

The Kibana / ES user needs **read-only** access to:

- The configured index pattern (default `filebeat-*`).
- `_search` and `_cluster/health` (or Kibana `/api/status`).

It does **not** need cluster management or write privileges. We recommend a
dedicated `appsec-reader` role with only these grants.

## SARIF ingest

The output validates against the SARIF 2.1.0 schema. Verified ingesters:

- **GitHub code scanning** — direct via `github/codeql-action/upload-sarif`.
- **DefectDojo** — import as SARIF.
- **SonarQube** — via the SARIF importer plugin.

Each finding carries `partialFingerprints["primaryLocationLineHash/v1"]` for
stable cross-run tracking. Code-review findings reference `file:line:column`;
log-review findings reference `<index>/<doc-id>` plus a Kibana Discover deep-link
in `properties.logEvidence.kibanaUrl`.

## Baseline workflow

1. Initial run on a clean branch:
   ```bash
   code-review --update-baseline --baseline .security-baseline.json --path ./src
   ```
2. Commit the baseline to the repository.
3. Subsequent CI runs reference the baseline:
   ```bash
   code-review --baseline .security-baseline.json --path ./src --fail-on HIGH
   ```
4. To refresh after triage:
   ```bash
   code-review --update-baseline --baseline .security-baseline.json --path ./src
   ```

The baseline file contains only stable content fingerprints — no source snippets,
no PII. Safe to commit even when source contains real secrets.

## Performance notes

| Workload | Wall time | Peak RSS |
| --- | --- | --- |
| 100 LoC | ~0.3 s | ~150 MB |
| 5 000 LoC | ~1.1 s | ~210 MB |
| 50 000 LoC | ~3 s | ~225 MB |
| Log scan, 15 days, 1 container, 10 000 hits | ~30 s | ~250 MB |

Log scans are I/O-bound on the Kibana side. The client uses HTTP keep-alive and
search-after pagination, so wall time scales linearly with hit count.

## Troubleshooting

- **"Kibana/ES auth failed: HTTP 401"** — verify `KIBANA_PASSWORD`. The error
  message will not contain the password.
- **"TTY detected"** on `--password-stdin` — pipe the password instead of typing
  it; the flag is for non-interactive use.
- **"Log scan aborted by caller"** — SIGINT received; findings already retrieved
  are flushed before exit.
- **SARIF validation errors in downstream tools** — confirm the tool understands
  SARIF 2.1.0. Older SonarQube versions may need an importer plugin update.
