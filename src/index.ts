import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { BackendCodeReviewAnalyzer, ExtendedAnalysisReport } from './analyzer';
import { JSONReporter } from './reporter';
import { SarifReporter } from './reporter/sarif';
import { Baseline } from './rules/baseline';
import { listRules, severityAtLeast } from './rules/registry';
import { Severity } from './types';
import { Logger } from './utils/logger';
import { KibanaClient, KibanaTransport, scrubCredentialsFromUrl } from './logs/kibanaClient';
import { LogReviewAnalyzer } from './logs/logReviewAnalyzer';
import { SearchAnalyzer, SearchReport } from './logs/searchAnalyzer';

// Interop-safe yargs resolution. Under plain CJS (tsc `dist/`, ts-node) `require('yargs/yargs')`
// returns the factory function directly. When this file is bundled (esbuild single-file release),
// the resolver may pull yargs' ESM build, in which case the factory arrives as a `.default` member.
// `?? mod` covers both so the same source works in dev, tsc-build, and the bundled release.
const yargsModule = require('yargs/yargs') as
  | ((args?: readonly string[]) => import('yargs').Argv)
  | { default: (args?: readonly string[]) => import('yargs').Argv };
const yargs = (
  typeof yargsModule === 'function' ? yargsModule : yargsModule.default
) as (args?: readonly string[]) => import('yargs').Argv;
const helpersModule = require('yargs/helpers') as
  | typeof import('yargs/helpers')
  | { default: typeof import('yargs/helpers') };
const hideBin = (
  'hideBin' in helpersModule ? helpersModule.hideBin : helpersModule.default.hideBin
) as typeof import('yargs/helpers')['hideBin'];

/**
 * Tool version, resolved in a way that survives bundling. The esbuild release bundle
 * inlines `__BCR_VERSION__` via `--define`; the plain tsc/ts-node path leaves it undefined
 * (guarded by `typeof`) and reads package.json next to the compiled file. yargs' own
 * `.version()` auto-detection reads package.json by walking up from argv[1], which fails
 * inside the single-file bundle (no package.json there) — hence this explicit resolution.
 */
declare const __BCR_VERSION__: string | undefined;
function resolveVersion(): string {
  if (typeof __BCR_VERSION__ !== 'undefined' && __BCR_VERSION__) return __BCR_VERSION__;
  for (const candidate of [
    path.join(__dirname, '..', 'package.json'),
    path.join(__dirname, 'package.json'),
  ]) {
    try {
      const pkg = JSON.parse(fs.readFileSync(candidate, 'utf-8')) as { version?: string };
      if (pkg.version) return pkg.version;
    } catch {
      /* try next candidate */
    }
  }
  return '0.0.0';
}
const VERSION = resolveVersion();

type OutputFormat = 'json' | 'text' | 'sarif';
type RunMode = 'code' | 'logs' | 'search';

const VALID_FORMATS: OutputFormat[] = ['json', 'text', 'sarif'];
const VALID_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const VALID_MODES: RunMode[] = ['code', 'logs', 'search'];
const VALID_TRANSPORTS: KibanaTransport[] = ['kibana-proxy', 'direct'];

class CliUsageError extends Error {}

function parseFormat(value: unknown): OutputFormat {
  const normalized = String(value || 'json').toLowerCase();
  if (!(VALID_FORMATS as string[]).includes(normalized)) {
    throw new CliUsageError(`--format must be one of ${VALID_FORMATS.join(', ')} (got '${value}')`);
  }
  return normalized as OutputFormat;
}

function parseSeverityStrict(flagName: string, value: unknown, fallback?: Severity): Severity | undefined {
  if (value === undefined || value === null || value === '') return fallback;
  const normalized = String(value).toUpperCase();
  if (!(VALID_SEVERITIES as string[]).includes(normalized)) {
    throw new CliUsageError(`--${flagName} must be one of ${VALID_SEVERITIES.join(', ')} (got '${value}')`);
  }
  return normalized as Severity;
}

export async function runCli(args = hideBin(process.argv)): Promise<number> {
  try {
    const argv = await yargs(args)
      .option('mode', {
        alias: 'm',
        describe: `Review mode: 'code' (static SAST, default), 'logs' (Kibana / ES rule scan), 'search' (free-text Kibana query)`,
        type: 'string',
        default: 'code',
      })
      .option('query', {
        alias: 'q',
        describe: 'Free-text query — search mode only. Uses Elasticsearch query_string syntax. Container scope optional via --container.',
        type: 'string',
      })
      .option('path', {
        alias: 'p',
        describe: 'Path to analyze (file or directory) — code mode only',
        type: 'string',
        default: '.',
      })
      // ── Log review options (mode=logs) ──────────────────────────────────
      .option('kibana-url', {
        describe: 'Base URL of Kibana (or ES) — log review only. Env: KIBANA_URL',
        type: 'string',
      })
      .option('elasticsearch-url', {
        describe: 'Alias of --kibana-url for direct ES transport. Env: ELASTICSEARCH_URL',
        type: 'string',
      })
      .option('username', {
        alias: 'u',
        describe: 'Kibana / ES username. Env: KIBANA_USERNAME',
        type: 'string',
      })
      .option('password-stdin', {
        describe: 'Read Kibana / ES password from stdin (recommended). Otherwise set KIBANA_PASSWORD.',
        type: 'boolean',
        default: false,
      })
      .option('api-key-stdin', {
        describe: 'Read Kibana / ES API key from stdin. Otherwise set KIBANA_API_KEY (+ KIBANA_API_KEY_ID).',
        type: 'boolean',
        default: false,
      })
      .option('bearer-token-stdin', {
        describe: 'Read SSO bearer token from stdin (Okta / PingFederate / Cognito flow). Otherwise set KIBANA_BEARER_TOKEN.',
        type: 'boolean',
        default: false,
      })
      .option('container', {
        describe: 'Container name to filter (e.g. payments-svc). Env: CONTAINER_NAME',
        type: 'string',
      })
      .option('container-field', {
        describe: 'ES field carrying the container name. Default: kubernetes.container.name',
        type: 'string',
      })
      .option('log-index', {
        describe: 'Elasticsearch index pattern (e.g. filebeat-*). Env: LOG_INDEX',
        type: 'string',
      })
      .option('days', {
        describe: 'How many days back to scan (default: 15). Env: LOG_REVIEW_DAYS',
        type: 'number',
        default: 15,
      })
      .option('transport', {
        describe: `ES access transport: ${VALID_TRANSPORTS.join(', ')} (default: kibana-proxy).`,
        type: 'string',
        default: 'kibana-proxy',
      })
      .option('max-hits', {
        describe: 'Maximum log hits to scan per run (safety cap, default 50000).',
        type: 'number',
        default: 50_000,
      })
      .option('insecure', {
        describe: 'Skip TLS certificate verification for private-CA Kibana clusters.',
        type: 'boolean',
        default: false,
      })
      .option('output', {
        alias: 'o',
        describe: 'Output file path for the report',
        type: 'string',
      })
      .option('format', {
        alias: 'f',
        describe: `Output format (${VALID_FORMATS.join(', ')})`,
        type: 'string',
        default: 'json',
      })
      .option('include-heuristics', {
        alias: 'a',
        describe: 'Include lower-confidence heuristic findings in the report',
        type: 'boolean',
        default: false,
      })
      .option('min-severity', {
        describe: `Drop findings below this severity (${VALID_SEVERITIES.join(', ')})`,
        type: 'string',
      })
      .option('fail-on', {
        describe: `Exit non-zero only when findings of at least this severity remain (${VALID_SEVERITIES.join(', ')})`,
        type: 'string',
        default: 'HIGH',
      })
      .option('baseline', {
        describe: 'Path to a baseline JSON file. Findings present in the baseline are suppressed.',
        type: 'string',
      })
      .option('update-baseline', {
        describe: 'Write the current findings to the baseline file path and exit without failure semantics.',
        type: 'boolean',
        default: false,
      })
      .option('disable-rule', {
        describe: 'Rule ID(s) to disable. Can be passed multiple times or as a comma-separated list.',
        type: 'array',
      })
      .option('show-suppressed', {
        describe: 'Include suppressed findings (baseline / inline) in SARIF output for reviewer visibility.',
        type: 'boolean',
        default: false,
      })
      .option('list-rules', {
        describe: 'Print the rule catalog (id, severity, CWE, OWASP) and exit.',
        type: 'boolean',
        default: false,
      })
      .option('quiet', {
        describe: 'Suppress non-error console output',
        type: 'boolean',
        default: false,
      })
      .option('verbose', {
        describe: 'Enable verbose console output',
        type: 'boolean',
        default: false,
      })
      .option('log-format', {
        describe: 'Console log format (text, json)',
        type: 'string',
        default: 'text',
      })
      .option('fail-on-runtime-errors', {
        describe: 'Return a non-zero exit code when runtime analysis errors occur',
        type: 'boolean',
        default: true,
      })
      .example('$0 --path ./src --format sarif --output report.sarif', 'Emit SARIF for GitHub code scanning')
      .example('$0 --path ./src --min-severity HIGH --fail-on HIGH', 'CI gate on HIGH+ findings only')
      .example('$0 --update-baseline --baseline .security-baseline.json --path ./src', 'Snapshot baseline')
      .example('$0 --baseline .security-baseline.json --path ./src', 'Subsequent scans suppress baselined findings')
      .example('$0 --list-rules | jq .', 'Inspect the rule catalog')
      .help()
      .alias('help', 'h')
      .version(VERSION)
      // Reject unknown flags; previously yargs accepted anything and silently exited 0.
      .strict()
      .argv;

    const logFormat = String(argv['log-format'] || 'text').toLowerCase() === 'json' ? 'json' : 'text';

    Logger.configure({
      quiet: Boolean(argv.quiet),
      verbose: Boolean(argv.verbose),
      format: logFormat,
    });

    if (argv['list-rules']) {
      printRuleCatalog();
      return 0;
    }

    const mode = parseMode(argv.mode);
    const includeHeuristics = Boolean(argv['include-heuristics']);
    const minSeverity = parseSeverityStrict('min-severity', argv['min-severity']);
    const disabledRules = parseStringList(argv['disable-rule']);

    let report: ExtendedAnalysisReport;
    let getBaselineFindings: () => Parameters<typeof Baseline.write>[1];

    if (mode === 'search') {
      const code = await runFreeTextSearch(argv);
      return code;
    } else if (mode === 'logs') {
      const logResult = await runLogReview(argv, { includeHeuristics, minSeverity, disabledRules });
      if (typeof logResult === 'number') return logResult;
      report = logResult.report;
      getBaselineFindings = logResult.getBaselineFindings;
    } else {
      const targetPath = path.resolve(argv.path as string);

      Logger.info(`
╔═════════════════════════════════════════════╗
║   Backend Code Review - Node.js Analyzer    ║
╚═════════════════════════════════════════════╝
`);
      Logger.info(`📊 Analyzing: ${targetPath}\n`);

      const analyzer = new BackendCodeReviewAnalyzer();
      report = analyzer.analyze(targetPath, {
        includeHeuristics,
        minSeverity,
        baselinePath: argv['update-baseline'] ? undefined : (argv.baseline as string | undefined),
        disabledRules,
        showSuppressed: Boolean(argv['show-suppressed']),
      });
      getBaselineFindings = () => analyzer.getAllFindingsWithFingerprints();
    }

    // Update-baseline mode: write the current finding set to the baseline and exit 0.
    if (argv['update-baseline']) {
      const baselinePath = resolveDefaultBaselinePath(argv.baseline as string | undefined, mode, argv.path as string | undefined);
      try {
        Baseline.write(baselinePath, getBaselineFindings());
        Logger.success(`Baseline written to ${path.resolve(baselinePath)}`);
        return 0;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        Logger.error('Failed to write baseline', { error: errorMessage, baselinePath });
        return 1;
      }
    }

    const format = parseFormat(argv.format);
    const outputPath =
      (argv.output as string) ||
      defaultReportName('code-review', format === 'text' ? 'txt' : format === 'sarif' ? 'sarif' : 'json');

    try {
      writeReport(report, format, outputPath, Boolean(argv['show-suppressed']));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error('Failed to write output report', { error: errorMessage, outputPath });
      return 1;
    }

    JSONReporter.printSummary(report);

    const failOn = parseSeverityStrict('fail-on', argv['fail-on'], 'HIGH') ?? 'HIGH';
    const hasFailingFinding = report.findings.some((finding) =>
      severityAtLeast(finding.severity, failOn)
    );

    if (hasFailingFinding) {
      return 1;
    }
    if (report.hasRuntimeErrors && Boolean(argv['fail-on-runtime-errors'])) {
      return 1;
    }

    return 0;
  } catch (error) {
    if (error instanceof CliUsageError) {
      Logger.error(error.message);
      return 2;
    }
    const errorMessage = error instanceof Error ? error.message : String(error);
    Logger.error('Fatal error', { error: errorMessage });
    return 1;
  }
}

/**
 * Bank-compliance masking for the CLI banner. Mirrors the redaction in
 * SearchAnalyzer so the banner doesn't leak PAN / Emirates-ID / Bearer values
 * the user passed via `--query`.
 */
function maskCliQuery(query: string): string {
  return query.replace(/("[^"]+"|[^\s()]{4,})/g, (token) => {
    if (token.length <= 4) return '*'.repeat(token.length);
    return token.slice(0, 2) + '*'.repeat(token.length - 4) + token.slice(-2);
  });
}

function parseMode(value: unknown): RunMode {
  const normalized = String(value || 'code').toLowerCase();
  if (!(VALID_MODES as string[]).includes(normalized)) {
    throw new CliUsageError(`--mode must be one of ${VALID_MODES.join(', ')} (got '${value}')`);
  }
  return normalized as RunMode;
}

function parseTransport(value: unknown): KibanaTransport {
  const normalized = String(value || 'kibana-proxy').toLowerCase();
  if (!(VALID_TRANSPORTS as string[]).includes(normalized)) {
    throw new CliUsageError(`--transport must be one of ${VALID_TRANSPORTS.join(', ')} (got '${value}')`);
  }
  return normalized as KibanaTransport;
}

function envOrFlag(flagValue: unknown, envName: string): string | undefined {
  const flag = typeof flagValue === 'string' ? flagValue.trim() : undefined;
  if (flag) return flag;
  const env = process.env[envName];
  if (env && env.trim()) return env.trim();
  return undefined;
}

function readPasswordFromStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8').replace(/\r?\n$/, '')));
    process.stdin.on('error', reject);
  });
}

interface LogReviewExecResult {
  report: ExtendedAnalysisReport;
  getBaselineFindings: () => Parameters<typeof Baseline.write>[1];
}

async function runLogReview(
  argv: Record<string, unknown>,
  shared: { includeHeuristics: boolean; minSeverity: Severity | undefined; disabledRules: string[] | undefined }
): Promise<LogReviewExecResult | number> {
  // Resolve every credential / endpoint with env-var fallback. UAE bank policy: secrets
  // never on the command line — env vars or stdin only.
  const kibanaUrl = envOrFlag(argv['kibana-url'], 'KIBANA_URL') ?? envOrFlag(argv['elasticsearch-url'], 'ELASTICSEARCH_URL');
  const username = envOrFlag(argv.username, 'KIBANA_USERNAME');
  const container = envOrFlag(argv.container, 'CONTAINER_NAME');
  const containerField = envOrFlag(argv['container-field'], 'CONTAINER_FIELD') ?? 'kubernetes.container.name';
  const logIndex = envOrFlag(argv['log-index'], 'LOG_INDEX') ?? 'filebeat-*';
  const days = Number(argv.days ?? process.env.LOG_REVIEW_DAYS ?? 15);
  const transport = parseTransport(argv.transport);
  const maxHits = parsePositiveInt(argv['max-hits'], 50_000);
  const insecure = Boolean(argv.insecure);

  let password: string | undefined;
  let apiKeyId: string | undefined;
  let apiKey: string | undefined;
  let bearerToken: string | undefined;

  // Priority: explicit stdin flags → bearer env → api-key env → password env.
  if (argv['bearer-token-stdin']) {
    if (process.stdin.isTTY) throw new CliUsageError('--bearer-token-stdin requires stdin to be piped.');
    bearerToken = await readPasswordFromStdin();
  } else if (argv['api-key-stdin']) {
    if (process.stdin.isTTY) throw new CliUsageError('--api-key-stdin requires stdin to be piped.');
    apiKey = await readPasswordFromStdin();
    apiKeyId = process.env.KIBANA_API_KEY_ID;
  } else if (argv['password-stdin']) {
    if (process.stdin.isTTY) {
      throw new CliUsageError('--password-stdin requires stdin to be piped (e.g. `echo $PWD | bcr --password-stdin ...`). Detected a TTY.');
    }
    password = await readPasswordFromStdin();
  } else if (process.env.KIBANA_BEARER_TOKEN) {
    bearerToken = process.env.KIBANA_BEARER_TOKEN;
  } else if (process.env.KIBANA_API_KEY_ID && process.env.KIBANA_API_KEY) {
    apiKeyId = process.env.KIBANA_API_KEY_ID;
    apiKey = process.env.KIBANA_API_KEY;
  } else if (process.env.KIBANA_PASSWORD) {
    password = process.env.KIBANA_PASSWORD;
  }

  const missing: string[] = [];
  if (!kibanaUrl) missing.push('--kibana-url / KIBANA_URL');
  if (!container) missing.push('--container / CONTAINER_NAME');
  // Auth: bearer token OR API-key pair OR username + password.
  const hasBearer = !!bearerToken;
  const hasApiKey = !!apiKeyId && !!apiKey;
  if (!hasBearer && !hasApiKey) {
    if (!username) missing.push('--username / KIBANA_USERNAME (or KIBANA_API_KEY_ID + KIBANA_API_KEY, or KIBANA_BEARER_TOKEN)');
    if (!password) missing.push('KIBANA_PASSWORD env var (or --password-stdin, or KIBANA_API_KEY_ID + KIBANA_API_KEY, or --bearer-token-stdin)');
  }
  if (missing.length > 0) {
    throw new CliUsageError(`Log review missing required inputs:\n  - ${missing.join('\n  - ')}`);
  }
  if (!Number.isFinite(days) || days <= 0 || days > 365) {
    throw new CliUsageError(`--days must be a positive number ≤ 365 (got ${argv.days})`);
  }

  Logger.info(`
╔═════════════════════════════════════════════╗
║   Backend Code Review - Log Review Mode     ║
╚═════════════════════════════════════════════╝
`);
  Logger.info(`📡 Kibana: ${kibanaUrl}  (transport: ${transport})`);
  Logger.info(`🪵  Container: ${container}  on index ${logIndex}`);
  Logger.info(`⏱  Window: last ${days} days\n`);

  if (insecure) {
    Logger.warn('TLS certificate verification disabled (--insecure). Use only with trusted private CAs.');
  }

  // SIGINT / SIGTERM → graceful abort: flush whatever findings we already have.
  // SIGTERM is what Docker / k8s sends on graceful shutdown; missing it leaves the
  // scanner running until the orchestrator force-kills.
  const abortController = new AbortController();
  const onSignal = (sig: string) => () => {
    Logger.warn(`\nReceived ${sig}, finishing in-flight requests and flushing findings…`);
    abortController.abort();
  };
  const onSigint = onSignal('SIGINT');
  const onSigterm = onSignal('SIGTERM');
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);

  const client = new KibanaClient({
    baseUrl: kibanaUrl as string,
    username,
    password,
    apiKeyId,
    apiKey,
    bearerToken,
    transport,
    index: logIndex,
    containerField,
    rejectUnauthorized: !insecure,
    abortSignal: abortController.signal,
    onProgress: (hits) => {
      Logger.info(`  scanned ${hits.toLocaleString()} log entries…`);
    },
  });

  // Fail fast on bad creds before running a 50k-hit scan.
  try {
    const ping = await client.ping();
    if (!ping.ok) {
      throw new CliUsageError(`Kibana/ES auth failed: HTTP ${ping.status}. Body: ${scrubCredentialsFromUrl(ping.body.slice(0, 200))}`);
    }
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    throw new CliUsageError(`Could not reach Kibana/ES at ${kibanaUrl}: ${(error as Error).message}`);
  }

  const now = new Date();
  const fromIso = new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
  const toIso = now.toISOString();

  const analyzer = new LogReviewAnalyzer(client);
  try {
    const report = await analyzer.analyze({
      containerName: container as string,
      fromIso,
      toIso,
      includeHeuristics: shared.includeHeuristics,
      minSeverity: shared.minSeverity,
      baselinePath: argv['update-baseline'] ? undefined : (argv.baseline as string | undefined),
      disabledRules: shared.disabledRules,
      maxHits,
    });
    return {
      report,
      getBaselineFindings: () => report.findings,
    };
  } finally {
    process.off('SIGINT', onSigint);
    process.off('SIGTERM', onSigterm);
  }
}

/**
 * Free-text search across Kibana / Elasticsearch. Same auth / transport / abort
 * controls as log-review mode but with no rule engine — just streams matching hits.
 */
async function runFreeTextSearch(argv: Record<string, unknown>): Promise<number> {
  const kibanaUrl = envOrFlag(argv['kibana-url'], 'KIBANA_URL') ?? envOrFlag(argv['elasticsearch-url'], 'ELASTICSEARCH_URL');
  const username = envOrFlag(argv.username, 'KIBANA_USERNAME');
  const container = envOrFlag(argv.container, 'CONTAINER_NAME');
  const containerField = envOrFlag(argv['container-field'], 'CONTAINER_FIELD') ?? 'kubernetes.container.name';
  // Search defaults to broad index — the user explicitly asked for "entire kibana".
  const logIndex = envOrFlag(argv['log-index'], 'LOG_INDEX') ?? '*';
  const days = Number(argv.days ?? process.env.LOG_REVIEW_DAYS ?? 7); // shorter default for search
  const transport = parseTransport(argv.transport);
  const maxHits = parsePositiveInt(argv['max-hits'], 200);
  const insecure = Boolean(argv.insecure);
  const query = typeof argv.query === 'string' ? argv.query : '';

  let password: string | undefined;
  let apiKeyId: string | undefined;
  let apiKey: string | undefined;
  let bearerToken: string | undefined;

  if (argv['bearer-token-stdin']) {
    if (process.stdin.isTTY) throw new CliUsageError('--bearer-token-stdin requires stdin to be piped.');
    bearerToken = await readPasswordFromStdin();
  } else if (argv['api-key-stdin']) {
    if (process.stdin.isTTY) throw new CliUsageError('--api-key-stdin requires stdin to be piped.');
    apiKey = await readPasswordFromStdin();
    apiKeyId = process.env.KIBANA_API_KEY_ID;
  } else if (argv['password-stdin']) {
    if (process.stdin.isTTY) throw new CliUsageError('--password-stdin requires stdin to be piped.');
    password = await readPasswordFromStdin();
  } else if (process.env.KIBANA_BEARER_TOKEN) {
    bearerToken = process.env.KIBANA_BEARER_TOKEN;
  } else if (process.env.KIBANA_API_KEY_ID && process.env.KIBANA_API_KEY) {
    apiKeyId = process.env.KIBANA_API_KEY_ID;
    apiKey = process.env.KIBANA_API_KEY;
  } else if (process.env.KIBANA_PASSWORD) {
    password = process.env.KIBANA_PASSWORD;
  }

  const missing: string[] = [];
  if (!kibanaUrl) missing.push('--kibana-url / KIBANA_URL');
  if (!query.trim()) missing.push('--query / -q (the search string)');
  const hasBearer = !!bearerToken;
  const hasApiKey = !!apiKeyId && !!apiKey;
  if (!hasBearer && !hasApiKey) {
    if (!username) missing.push('--username / KIBANA_USERNAME (or KIBANA_API_KEY_ID + KIBANA_API_KEY, or KIBANA_BEARER_TOKEN)');
    if (!password) missing.push('KIBANA_PASSWORD env var (or --password-stdin, or --bearer-token-stdin)');
  }
  if (missing.length > 0) {
    throw new CliUsageError(`Search mode missing required inputs:\n  - ${missing.join('\n  - ')}`);
  }
  if (!Number.isFinite(days) || days <= 0 || days > 365) {
    throw new CliUsageError(`--days must be a positive number ≤ 365 (got ${argv.days})`);
  }

  Logger.info(`
╔═════════════════════════════════════════════╗
║   Backend Code Review - Search Mode         ║
╚═════════════════════════════════════════════╝
`);
  Logger.info(`📡 Kibana: ${kibanaUrl}  (transport: ${transport})`);
  // Mask the query banner so PAN / Emirates-ID / Bearer leaks in the user's own
  // search term don't end up in stdout/CI capture. The user already knows what
  // they searched; reviewers reading the artifact don't need the raw value.
  Logger.info(`🔎 Query : ${maskCliQuery(query)}`);
  Logger.info(`📂 Index : ${logIndex}${container ? `  Container: ${container}` : '  Container: (all)'}`);
  Logger.info(`⏱  Window: last ${days} days  (max ${maxHits} hits)\n`);

  if (insecure) {
    Logger.warn('TLS certificate verification disabled (--insecure).');
  }

  const abortController = new AbortController();
  const onSigint = () => {
    Logger.warn('\nReceived SIGINT, flushing collected hits…');
    abortController.abort();
  };
  const onSigterm = () => {
    Logger.warn('\nReceived SIGTERM, flushing collected hits…');
    abortController.abort();
  };
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);

  const client = new KibanaClient({
    baseUrl: kibanaUrl as string,
    username, password, apiKeyId, apiKey, bearerToken,
    transport, index: logIndex, containerField,
    rejectUnauthorized: !insecure,
    abortSignal: abortController.signal,
    onProgress: (n) => Logger.info(`  matched ${n.toLocaleString()} hits so far…`),
  });

  try {
    const ping = await client.ping();
    if (!ping.ok) {
      throw new CliUsageError(`Kibana/ES auth failed: HTTP ${ping.status}.`);
    }
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    throw new CliUsageError(`Could not reach Kibana/ES: ${(error as Error).message}`);
  }

  const now = new Date();
  const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
  const to = now.toISOString();

  let report: SearchReport;
  try {
    const analyzer = new SearchAnalyzer(client);
    report = await analyzer.search({
      query: query.trim(),
      containerName: container,
      from, to,
      maxHits,
    });
  } finally {
    process.off('SIGINT', onSigint);
    // SIGTERM was registered but never removed — a handler leak that accumulated a listener per
    // in-process invocation (and could trip Node's MaxListenersExceededWarning).
    process.off('SIGTERM', onSigterm);
  }

  const format = parseFormat(argv.format);
  const outputPath = (argv.output as string)
    || defaultReportName('search', format === 'text' ? 'txt' : 'json');

  try {
    ensureParentDir(outputPath);
    if (format === 'text') {
      fs.writeFileSync(outputPath, formatSearchReportText(report), 'utf-8');
    } else {
      fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
    }
    Logger.success(`Search results written to ${outputPath}`);
  } catch (error) {
    Logger.error('Failed to write search results', { error: (error as Error).message });
    return 1;
  }

  if (typeof report.matchedTotal === 'number' && report.matchedTotal > report.totalHits) {
    const approx = report.matchedTotalRelation === 'gte' ? '≥' : '';
    Logger.info(`\n✓ showing ${report.totalHits} of ${approx}${report.matchedTotal.toLocaleString()} matching document(s)`);
  } else {
    Logger.info(`\n✓ ${report.totalHits} hit(s) matched`);
  }
  if (report.truncated) {
    Logger.warn(`Results truncated at --max-hits (${maxHits}). Tighten the query or narrow --days.`);
  }
  // Search mode never sets exit=1 on "found hits" — it's an investigative tool, not
  // a compliance gate. Exit 0 always (unless we couldn't reach Kibana).
  return 0;
}

function formatSearchReportText(report: SearchReport): string {
  const lines: string[] = [];
  lines.push(`Kibana free-text search`);
  lines.push(`Query     : ${report.query}`);
  lines.push(`Container : ${report.containerName ?? '(all)'}`);
  lines.push(`Window    : ${report.fromIso}  →  ${report.toIso}`);
  lines.push(`Hits      : ${report.totalHits}${report.truncated ? ' (truncated)' : ''}`);
  if (typeof report.matchedTotal === 'number' && report.matchedTotal > report.totalHits) {
    lines.push(`Matched   : ${report.matchedTotalRelation === 'gte' ? '≥' : ''}${report.matchedTotal} (returned ${report.totalHits})`);
  }
  lines.push(`Duration  : ${report.durationMs} ms`);
  lines.push('');
  report.hits.forEach((hit, index) => {
    lines.push(`[${index + 1}] ${hit.timestamp}  ${hit.index}/${hit.docId}`);
    if (hit.container) lines.push(`    container: ${hit.container}`);
    lines.push(`    kibana   : ${hit.kibanaUrl}`);
    lines.push(`    excerpt  : ${hit.excerpt}`);
    lines.push('');
  });
  return lines.join('\n');
}

function ensureParentDir(outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function writeReport(
  report: ExtendedAnalysisReport,
  format: OutputFormat,
  outputPath: string,
  includeSuppressed: boolean
): void {
  // Create the parent directory for every format. Previously only SARIF did this, so
  // `--output reports/out.json` threw ENOENT while `--output reports/out.sarif` worked.
  ensureParentDir(outputPath);

  if (format === 'sarif') {
    const sarif = SarifReporter.build(report, { includeSuppressed });
    fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
    Logger.success(`SARIF report saved to ${outputPath}`);
    return;
  }

  if (format === 'text') {
    JSONReporter.writeTextReport(report, outputPath);
    return;
  }

  JSONReporter.writeReport(report, outputPath);
}

/**
 * Parse a positive-integer flag, falling back to a default when the value is missing,
 * non-numeric, or non-positive. Without this, `--max-hits abc` becomes NaN and the
 * `yielded < maxHits` loop guard is always false, silently producing an empty scan.
 */
function parsePositiveInt(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.floor(n);
}

/**
 * Default output filename when `--output` is omitted. Includes the timestamp PLUS the pid and a
 * short random suffix so two runs started in the same millisecond (parallel CI shards, a tight
 * loop) can't clobber each other's report — `Date.now()` alone collides at sub-ms cadence.
 */
function defaultReportName(prefix: string, ext: string): string {
  const rand = crypto.randomBytes(3).toString('hex');
  return `${prefix}-${Date.now()}-${process.pid}-${rand}.${ext}`;
}

/**
 * Resolve where `--update-baseline` writes when `--baseline` isn't given. For a code scan we
 * co-locate the baseline with the code it describes (so a sub-path scan like
 * `--path services/payments` writes `services/payments/.security-baseline.json`, not a stray file
 * in the cwd of whoever ran it). For logs/search there's no scanned path, so fall back to cwd.
 */
function resolveDefaultBaselinePath(explicit: string | undefined, mode: RunMode, scanPath: string | undefined): string {
  if (explicit) return explicit;
  if (mode === 'code' && scanPath) {
    try {
      const resolved = path.resolve(scanPath);
      const dir = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
      return path.join(dir, '.security-baseline.json');
    } catch {
      /* fall through to cwd default */
    }
  }
  return '.security-baseline.json';
}

function parseStringList(input: unknown): string[] | undefined {
  if (!input) return undefined;
  if (Array.isArray(input)) {
    return input
      .flatMap((entry) => String(entry).split(','))
      .map((value) => value.trim())
      .filter(Boolean);
  }
  return String(input)
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function printRuleCatalog(): void {
  const rules = listRules();
  const rows = rules.map((rule) => ({
    id: rule.id,
    severity: rule.defaultSeverity,
    category: rule.category,
    heuristic: rule.heuristic ? 'yes' : 'no',
    cwe: rule.cwe,
    owasp: rule.owasp,
    title: rule.title,
    description: rule.description,
  }));
  // Write to stdout directly so `node dist/index.js --list-rules | jq .` works.
  // Logger.info routes to stderr because the analyzer output normally pipes through
  // stdout — but here the catalog IS the output.
  process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
}

/**
 * Drain stdout/stderr before exiting. `process.exit()` does NOT wait for buffered stdout to flush,
 * so piping large output (e.g. `--list-rules | jq`) could truncate the JSON mid-write. Writing an
 * empty chunk with a callback resolves only once the stream's buffer has been handed to the OS.
 */
function flushStdio(): Promise<void> {
  const drain = (stream: NodeJS.WriteStream): Promise<void> =>
    new Promise((resolve) => {
      // `write('')` invokes the callback after the internal buffer is flushed; if the stream is
      // already drained it resolves on the next tick. Guard against a missing callback path.
      if (!stream.write('')) {
        stream.once('drain', () => resolve());
      } else {
        resolve();
      }
    });
  return Promise.all([drain(process.stdout), drain(process.stderr)]).then(() => undefined);
}

async function main() {
  const code = await runCli();
  await flushStdio();
  process.exit(code);
}

if (require.main === module) {
  void main();
}
