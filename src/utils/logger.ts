type LogLevel = 'debug' | 'info' | 'success' | 'warn' | 'error';
type LogFormat = 'text' | 'json';

interface LoggerConfig {
  quiet: boolean;
  verbose: boolean;
  format: LogFormat;
  suppressRuntimeIssueLogs: boolean;
}

interface LogMeta {
  [key: string]: unknown;
}

export class Logger {
  private static config: LoggerConfig = {
    quiet: false,
    verbose: false,
    format: 'text',
    suppressRuntimeIssueLogs: false,
  };

  static configure(config: Partial<LoggerConfig>): void {
    this.config = {
      ...this.config,
      ...config,
    };
  }

  static getConfig(): LoggerConfig {
    return { ...this.config };
  }

  static debug(message: string, meta?: LogMeta): void {
    if (!this.config.verbose) {
      return;
    }

    this.emit('debug', message, meta);
  }

  static info(message: string, meta?: LogMeta): void {
    if (this.config.quiet) {
      return;
    }

    this.emit('info', message, meta);
  }

  static success(message: string, meta?: LogMeta): void {
    if (this.config.quiet) {
      return;
    }

    this.emit('success', message, meta);
  }

  static warn(message: string, meta?: LogMeta): void {
    if (this.config.quiet) {
      return;
    }

    this.emit('warn', message, meta);
  }

  static error(message: string, meta?: LogMeta): void {
    this.emit('error', message, meta);
  }

  static runtimeWarn(message: string, meta?: LogMeta): void {
    if (this.config.suppressRuntimeIssueLogs || this.config.quiet) {
      return;
    }

    this.emit('warn', message, meta);
  }

  static runtimeError(message: string, meta?: LogMeta): void {
    if (this.config.suppressRuntimeIssueLogs) {
      return;
    }

    this.emit('error', message, meta);
  }

  private static emit(level: LogLevel, message: string, meta?: LogMeta): void {
    const output = this.config.format === 'json'
      ? JSON.stringify({
          level,
          message,
          ...(meta ?? {}),
        })
      : this.formatText(level, message, meta);

    if (level === 'warn' || level === 'error') {
      console.error(output);
      return;
    }

    console.log(output);
  }

  private static formatText(level: LogLevel, message: string, meta?: LogMeta): string {
    const prefix: Record<LogLevel, string> = {
      debug: '•',
      info: '',
      success: '✓',
      warn: '⚠️',
      error: '✗',
    };
    const suffix = meta && Object.keys(meta).length > 0
      ? ` ${JSON.stringify(meta)}`
      : '';
    const levelPrefix = prefix[level];
    return levelPrefix ? `${levelPrefix} ${message}${suffix}` : `${message}${suffix}`;
  }
}
