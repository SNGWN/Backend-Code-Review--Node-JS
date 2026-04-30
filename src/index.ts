import * as path from 'path';
import { BackendCodeReviewAnalyzer } from './analyzer';
import { JSONReporter } from './reporter';
import { Logger } from './utils/logger';

const yargs = require('yargs/yargs') as (args?: readonly string[]) => import('yargs').Argv;
const { hideBin } = require('yargs/helpers') as typeof import('yargs/helpers');

export async function runCli(args = hideBin(process.argv)): Promise<number> {
  try {
    const argv = await yargs(args)
      .option('path', {
        alias: 'p',
        describe: 'Path to analyze (file or directory)',
        type: 'string',
        default: '.',
      })
      .option('output', {
        alias: 'o',
        describe: 'Output file path for the report',
        type: 'string',
      })
      .option('format', {
        alias: 'f',
        describe: 'Output format (json, text)',
        type: 'string',
        default: 'json',
      })
      .option('include-heuristics', {
        alias: 'a',
        describe: 'Include lower-confidence heuristic findings in the report',
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
      .help()
      .alias('help', 'h')
      .version()
      .argv;

    const targetPath = path.resolve(argv.path as string);
    const logFormat = String(argv['log-format'] || 'text').toLowerCase() === 'json' ? 'json' : 'text';

    Logger.configure({
      quiet: Boolean(argv.quiet),
      verbose: Boolean(argv.verbose),
      format: logFormat,
    });

    Logger.info(`
╔═════════════════════════════════════════════╗
║   Backend Code Review - Node.js Analyzer    ║
╚═════════════════════════════════════════════╝
`);
    Logger.info(`📊 Analyzing: ${targetPath}\n`);

    const analyzer = new BackendCodeReviewAnalyzer();
    const includeHeuristics = Boolean(argv['include-heuristics']);
    const report = analyzer.analyze(targetPath, { includeHeuristics });

    const format = String(argv.format || 'json').toLowerCase();
    const outputPath =
      (argv.output as string) ||
      `code-review-${Date.now()}.${format === 'text' ? 'txt' : 'json'}`;

    try {
      if (format === 'text') {
        JSONReporter.writeTextReport(report, outputPath);
      } else {
        JSONReporter.writeReport(report, outputPath);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error('Failed to write output report', { error: errorMessage, outputPath });
      return 1;
    }

    JSONReporter.printSummary(report);

    if (report.totalFindings > 0) {
      return 1;
    }
    if (report.hasRuntimeErrors && Boolean(argv['fail-on-runtime-errors'])) {
      return 1;
    }

    return 0;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    Logger.error('Fatal error', { error: errorMessage });
    return 1;
  }
}

async function main() {
  process.exit(await runCli());
}

if (require.main === module) {
  void main();
}
