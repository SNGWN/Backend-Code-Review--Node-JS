import * as fs from 'fs';
import * as path from 'path';
import fg from 'fast-glob';
import ignore from 'ignore';
import { VALIDATION_LIBRARIES } from './constants';
import { Logger } from './logger';

interface FileDiscoveryOptions {
  ignorePatterns?: string[];
  respectGitIgnore?: boolean;
}

/**
 * File system utility class for reading and discovering TypeScript files
 */
export class FileHelper {
  /**
   * Recursively finds all TypeScript (.ts, .tsx) files in a directory
   * Automatically skips ignored/generated directories and declaration files
   *
   * @param dirPath - Root directory path to search
   * @returns Array of absolute file paths for all TypeScript files found
   *
   * @example
   * const files = FileHelper.getAllTypeScriptFiles('./src');
   * // Returns: ['/path/to/src/app.ts', '/path/to/src/routes.ts', ...]
   */
  static getAllTypeScriptFiles(dirPath: string, options: FileDiscoveryOptions = {}): string[] {
    const searchRoot = path.resolve(dirPath);
    const ignoreMatcher = options.respectGitIgnore ? this.loadGitIgnoreMatcher(searchRoot) : null;

    try {
      const files = fg.sync(['**/*.ts', '**/*.tsx'], {
        cwd: searchRoot,
        absolute: true,
        onlyFiles: true,
        unique: true,
        dot: false,
        ignore: ['**/*.d.ts', '**/node_modules/**', ...(options.ignorePatterns ?? [])],
      });

      return files
        .filter((filePath) => !this.isIgnoredByMatcher(filePath, searchRoot, ignoreMatcher))
        .sort();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error(`Error reading directory ${dirPath}`, { error: errorMessage });
      return [];
    }
  }

  /**
   * Reads the contents of a file
   *
   * @param filePath - Path to the file to read
   * @returns File contents as a string, or empty string if read fails
   *
   * @example
   * const content = FileHelper.readFile('./src/app.ts');
   */
  static readFile(filePath: string): string {
    try {
      return fs.readFileSync(filePath, 'utf-8');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      Logger.error(`Error reading file ${filePath}`, { error: errorMessage });
      return '';
    }
  }

  /**
   * Checks if a path points to a directory
   *
   * @param dirPath - Path to check
   * @returns true if the path is a directory, false otherwise
   */
  static isDirectory(dirPath: string): boolean {
    try {
      return fs.statSync(dirPath).isDirectory();
    } catch {
      return false;
    }
  }

  /**
   * Checks if a path points to a file
   *
   * @param filePath - Path to check
   * @returns true if the path is a file, false otherwise
   */
  static isFile(filePath: string): boolean {
    try {
      return fs.statSync(filePath).isFile();
    } catch {
      return false;
    }
  }

  private static loadGitIgnoreMatcher(searchRoot: string) {
    const gitignorePaths = [path.join(process.cwd(), '.gitignore')];
    if (searchRoot !== process.cwd()) {
      gitignorePaths.push(path.join(searchRoot, '.gitignore'));
    }

    const patterns = gitignorePaths
      .filter((gitignorePath, index, allPaths) => allPaths.indexOf(gitignorePath) === index && fs.existsSync(gitignorePath))
      .map((gitignorePath) => fs.readFileSync(gitignorePath, 'utf-8'));

    if (patterns.length === 0) {
      return null;
    }

    return ignore().add(patterns.join('\n'));
  }

  private static isIgnoredByMatcher(
    filePath: string,
    searchRoot: string,
    ignoreMatcher: ReturnType<typeof ignore> | null
  ): boolean {
    if (!ignoreMatcher) {
      return false;
    }

    const cwdRelativePath = path.relative(process.cwd(), filePath);
    const rootRelativePath = path.relative(searchRoot, filePath);
    const candidatePath = !cwdRelativePath.startsWith('..')
      ? cwdRelativePath
      : rootRelativePath;

    return ignoreMatcher.ignores(candidatePath.split(path.sep).join('/'));
  }
}

/**
 * String utility class for pattern matching and detection helpers
 *
 * Provides methods for:
 * - Detecting sensitive data patterns (passwords, tokens, API keys)
 * - Identifying validation library calls
 * - Recognizing authentication patterns
 * - Detecting logging statements
 */
export class StringHelper {
  /**
   * Detects sensitive data patterns in a string
   * Searches for passwords, API keys, tokens, PII, and other sensitive information
   *
   * @param str - The string to analyze
   * @returns Array of detected sensitive patterns (deduplicated)
   *
   * @example
   * const patterns = StringHelper.containsSensitivePatterns('password=secret123');
   * // Returns: ['password', 'secret']
   */
  static containsSensitivePatterns(str: string): string[] {
    const patterns = [
      /password|pwd|passwd/gi,
      /api[_-]?key|apikey|secret/gi,
      /token|access[_-]token|refresh[_-]token/gi,
      /bearer\s+[\w\-\.]+/gi,
      /authorization|auth\s*:/gi,
      /credit[_-]?card|cc|ssn|social[_-]security/gi,
      /email|user[_-]?id|user[_-]?name/gi,
      /private[_-]?key|public[_-]?key|cert/gi,
    ];

    const matches: string[] = [];
    for (const pattern of patterns) {
      const match = str.match(pattern);
      if (match) {
        matches.push(...match);
      }
    }

    return [...new Set(matches)];
  }

  /**
   * Checks if a function name indicates a validation library call
   * Recognizes common validation libraries: joi, yup, zod, validator, express-validator
   *
   * @param functionName - The name of the function to check
   * @returns true if the function appears to be a validation call
   *
   * @example
   * StringHelper.isValidationLibraryCall('joi.object()');  // true
   * StringHelper.isValidationLibraryCall('yup.string()');  // true
   * StringHelper.isValidationLibraryCall('parseInt()');    // false
   */
  static isValidationLibraryCall(functionName: string): boolean {
    return VALIDATION_LIBRARIES.some((lib) =>
      functionName.toLowerCase().includes(lib)
    );
  }

  /**
   * Checks if a function name indicates sanitization/escaping
   * Recognizes common sanitization functions
   *
   * @param functionName - The name of the function to check
   * @returns true if the function appears to be a sanitization call
   *
   * @example
   * StringHelper.isSanitizationCall('sanitize()');      // true
   * StringHelper.isSanitizationCall('htmlEscape()');    // true
   * StringHelper.isSanitizationCall('process()');       // false
   */
  static isSanitizationCall(functionName: string): boolean {
    const sanitizationFunctions = [
      'sanitize',
      'escape',
      'encodeuri',
      'encodeuricomponent',
      'htmlescape',
      'dompurify',
      'xss',
    ];

    return sanitizationFunctions.some((fn) =>
      functionName.toLowerCase().includes(fn)
    );
  }

  /**
   * Checks if a function name indicates authentication middleware
   * Used to identify middleware that protects routes
   *
   * @param functionName - The name of the function to check
   * @returns true if the function appears to be authentication middleware
   *
   * @example
   * StringHelper.isAuthenticationMiddleware('authenticateToken');  // true
   * StringHelper.isAuthenticationMiddleware('verifyJWT');          // true
   * StringHelper.isAuthenticationMiddleware('processData()');      // false
   */
  static isAuthenticationMiddleware(functionName: string): boolean {
    const authPatterns = [
      'auth',
      'verify',
      'authenticate',
      'middleware',
      'guard',
      'protector',
      'permission',
    ];

    return authPatterns.some((pattern) =>
      functionName.toLowerCase().includes(pattern)
    );
  }

  /**
   * Checks if a function name indicates a logging call
   * Recognizes console methods and popular logging libraries
   *
   * @param functionName - The name of the function to check
   * @returns true if the function appears to be a logging call
   *
   * @example
   * StringHelper.isLoggerCall('console.log');     // true
   * StringHelper.isLoggerCall('logger.warn');    // true
   * StringHelper.isLoggerCall('calculateSum()'); // false
   */
  static isLoggerCall(functionName: string): boolean {
    const loggerPatterns = [
      'log',
      'debug',
      'info',
      'warn',
      'error',
      'trace',
      'console',
      'logger',
      'winston',
      'pino',
    ];

    return loggerPatterns.some((pattern) =>
      functionName.toLowerCase().includes(pattern)
    );
  }
}
