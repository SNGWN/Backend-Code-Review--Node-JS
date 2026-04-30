/**
 * Shared Constants for Detection Patterns
 *
 * Centralized location for regex patterns and keyword lists used across
 * multiple detectors. This reduces duplication and makes patterns easier to maintain.
 */

/**
 * Keywords that indicate sensitive data (passwords, tokens, API keys, etc.)
 * Used by authentication and logging detectors
 */
export const SENSITIVE_KEYWORDS = [
  'secret',
  'password',
  'pwd',
  'api_key',
  'apikey',
  'api-key',
  'token',
  'access_token',
  'refresh_token',
  'bearer',
  'authorization',
  'auth',
  'credential',
  'credentials',
  'private_key',
  'privatekey',
  'oauth',
];

/**
 * Regex patterns for detecting sensitive data in logs and code
 */
export const SENSITIVE_DATA_PATTERNS = {
  // Credit card patterns (simplified)
  creditCard: /\b(?:\d{4}[\s-]?){3}\d{4}\b/,

  // Social Security Number patterns
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,

  // Email addresses
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,

  // Hex-like strings (tokens, keys) - 16+ hex chars
  hexString: /\b[a-fA-F0-9]{16,}\b/,

  // Base64-like strings (32+ chars of alphanumeric + / + = )
  base64: /\b[A-Za-z0-9+/]{32,}={0,2}\b/,

  // UUID patterns
  uuid: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/,

  // Private key markers
  privateKey: /-----BEGIN\s+(PRIVATE|RSA|DSA|EC|PGP)\s+KEY/i,

  // AWS access key patterns
  awsKey: /AKIA[0-9A-Z]{16}/,
};

/**
 * Common validation library names
 * Used by the validation detector to identify when input has been validated
 */
export const VALIDATION_LIBRARIES = [
  'joi',
  'yup',
  'zod',
  'validator',
  'express-validator',
  'validate',
  'valibot',
  'superstruct',
];

/**
 * HTTP method names for detecting route handlers
 * Used by the authentication detector to find route definitions
 */
export const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];

/**
 * Authentication verification function names
 * Used to determine if a token or user has been verified
 */
export const AUTH_VERIFICATION_FUNCTIONS = [
  'verify',
  'validate',
  'authenticate',
  'authorize',
  'decode',
  'check',
  'verify_token',
  'validateToken',
  'checkAuth',
];

/**
 * Sensitive operation indicators
 * Functions/methods that likely perform sensitive operations
 * Used to identify operations that should have auth guards
 */
export const SENSITIVE_OPERATIONS = [
  'delete',
  'admin',
  'private',
  'internal',
  'secret',
  'payment',
  'billing',
  'transaction',
];

/**
 * Keywords that suggest logging sensitive data
 * Used by the logging detector
 */
export const SENSITIVE_LOG_KEYWORDS = [
  'password',
  'secret',
  'token',
  'api_key',
  'apikey',
  'credential',
  'ssn',
  'credit_card',
  'auth',
  'private',
];

/**
 * Log level names and their typical uses
 * Used by the logging detector to check for appropriate log levels
 */
export const LOG_LEVELS = {
  debug: 'Detailed information for debugging',
  info: 'General informational messages',
  warn: 'Warning messages for potentially problematic situations',
  error: 'Error messages for failures',
  fatal: 'Fatal error messages',
};

/**
 * Property names commonly used for mass assignment vulnerabilities
 * Used by the mass assignment detector
 */
export const DANGEROUS_PROPERTIES = [
  '__proto__',
  'constructor',
  'prototype',
  'admin',
  'role',
  'isAdmin',
  'permissions',
  'deleted',
];

/**
 * Field names that are often whitelisted in secure applications
 * Used to suggest which fields should be allowed
 */
export const COMMONLY_WHITELISTED_FIELDS = [
  'email',
  'name',
  'phone',
  'address',
  'bio',
  'avatar',
  'profile',
  'username',
];

/**
 * Documentation and detector logic strings that should be excluded
 * from vulnerability detection (to avoid false positives)
 */
export const DETECTOR_LOGIC_STRINGS = [
  'secret, password, or key appears to be hardcoded',
  'move secrets to environment',
  'remove sensitive data from logs',
  'mask or redact passwords',
  'tokens, api keys, and pii',
  'sensitive data in logs',
  'hardcoded secret in variable',
  'variable contains a hardcoded secret',
  'unvalidated request',
  'missing validation',
  'missing authentication',
];

/**
 * Common configuration file names
 * Used by validators to check if validation is in separate config
 */
export const CONFIG_FILE_PATTERNS = [
  '.env',
  '.env.local',
  'config.js',
  'config.ts',
  'config.json',
  'settings.js',
  'settings.ts',
  'config.development.js',
  'config.production.js',
];

/**
 * Framework-specific request object patterns
 * Used to identify where user input comes from
 */
export const REQUEST_OBJECT_PATTERNS = {
  express: ['req.body', 'req.params', 'req.query', 'req.headers'],
  nestjs: ['@Body()', '@Param()', '@Query()', '@Headers()'],
  fastify: ['request.body', 'request.params', 'request.query', 'request.headers'],
};
