// LOGGING FP exhibits. Zero default findings expected.

const logger = {
  info: (..._args: unknown[]) => {},
  warn: (..._args: unknown[]) => {},
  error: (..._args: unknown[]) => {},
  debug: (..._args: unknown[]) => {},
};

// (1) Plain structured logs with PII-LABEL field names but no actual credentials.
logger.info('user updated', { userId: 1 });
logger.info('user signed in', { userId: 1, email: 'a@b.com' });
logger.info('account event', { username: 'alice' });

// (2) Strings that include the WORD password/token but not as data.
logger.info('password reset link sent');
logger.info('token refresh succeeded');
logger.warn('certificate expired soon');

// (3) Logs that contain words with `cc` substring — should never fire on credit-card.
logger.info('record deleted successfully');
logger.info('connection accepted');
logger.info('cache occurred at boot');

// (4) Logs with safe metadata (boolean flags, durations).
logger.debug('request finished', { durationMs: 12, hasAuth: true });

// (5) Template literals interpolating non-request values.
const orderId = 'ord-123';
logger.info(`Order ${orderId} processed`);

// (6) Errors with sanitized messages.
try {
  doWork();
} catch (e) {
  logger.error('work failed', { code: (e as { code?: string }).code });
}
function doWork(): void {}
