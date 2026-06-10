/**
 * Shared constants for detection patterns.
 *
 * Only constants with at least one consumer live here — dead pattern lists that no
 * detector reads get removed rather than maintained (they drift from the real logic
 * and mislead contributors about what the detectors actually match).
 */

/**
 * Common validation library names.
 * Used by the validation detector to identify when input has been validated.
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
 * HTTP method names for detecting route handlers.
 * Used to find route definitions (e.g. `app.get(...)`, `router.post(...)`).
 */
export const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];
