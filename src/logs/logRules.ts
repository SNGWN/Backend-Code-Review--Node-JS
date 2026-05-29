import { Finding, IssueCategory, Severity } from '../types';
import { LogHit } from './kibanaClient';

/**
 * Log-scanner rules.
 *
 * Each rule consumes a single log line and returns zero or more findings. Rules
 * deliberately keep state-free (no cross-line context) so we can stream-scan
 * millions of lines without memory pressure.
 *
 * Precision discipline (critical for a UAE bank — false positives waste audit time):
 *   - PAN: digits-only Luhn validation. Card-test prefixes (4242…, 4111…) are valid PANs
 *     and SHOULD fire even in test data — that's the point in production logs.
 *   - IBAN: ISO 13616 format + mod-97 checksum. Plain `AE...` text without a valid
 *     checksum is dropped.
 *   - Emirates ID: 784-YYYY-XXXXXXX-X with year-range sanity (1900-current).
 *   - Email/phone/passport are marked heuristic — operational metadata vs customer
 *     identifier is a reviewer call.
 */

export interface LogRuleMatch {
  ruleId: string;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  category: IssueCategory;
  /** Start/end offsets in the line — used to build a redacted excerpt. */
  start: number;
  end: number;
  /** Raw matched substring. Used only for fingerprinting; NEVER shipped in the finding. */
  match: string;
}

export type LogRule = (line: string) => LogRuleMatch[];

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Luhn checksum. Returns true iff the input (digits only, length 12-19) passes.
 * https://en.wikipedia.org/wiki/Luhn_algorithm
 */
export function passesLuhn(digits: string): boolean {
  if (!/^\d{12,19}$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let value = digits.charCodeAt(i) - 48;
    if (alternate) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * ISO 13616 mod-97 IBAN checksum. Returns true iff the canonical IBAN passes.
 */
export function passesIbanMod97(iban: string): boolean {
  // Move first 4 chars (CCdd) to end, replace letters A-Z with 10-35, then mod 97.
  const canonical = iban.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(canonical)) return false;
  const rearranged = canonical.slice(4) + canonical.slice(0, 4);
  const digits = rearranged.replace(/[A-Z]/g, (ch) => String(ch.charCodeAt(0) - 55));
  // mod 97 over a long string — process in chunks to avoid BigInt allocations.
  let remainder = 0;
  for (let i = 0; i < digits.length; i++) {
    remainder = (remainder * 10 + (digits.charCodeAt(i) - 48)) % 97;
  }
  return remainder === 1;
}

/**
 * Builds a redacted excerpt of the matched line. We keep ~40 chars of context on each
 * side but mask the matched substring (keep first 2 + last 2 chars). PCI-DSS rules
 * forbid retaining the full PAN even in a security tool's output.
 *
 * Multi-rule safety: if `otherMatches` is provided, ALL other rule matches that
 * overlap the excerpt window are ALSO masked. Without this, a Bearer-finding's
 * excerpt would leak a co-located plaintext password (real PCI breach we caught
 * in the redaction-guarantee test).
 */
export function buildRedactedExcerpt(
  line: string,
  start: number,
  end: number,
  otherMatches: Array<{ start: number; end: number }> = []
): string {
  const left = Math.max(0, start - 40);
  const right = Math.min(line.length, end + 40);

  // Mask the primary match AND any other matches inside the window. We build the
  // excerpt by walking the substring [left, right) and substituting masked
  // characters at each match interval.
  const intervals: Array<{ start: number; end: number }> = [{ start, end }, ...otherMatches]
    .filter((m) => m.end > left && m.start < right)
    .map((m) => ({ start: Math.max(m.start, left), end: Math.min(m.end, right) }))
    .sort((a, b) => a.start - b.start);

  // Merge overlapping intervals so we don't double-mask.
  const merged: Array<{ start: number; end: number }> = [];
  for (const interval of intervals) {
    const last = merged[merged.length - 1];
    if (last && interval.start <= last.end) {
      last.end = Math.max(last.end, interval.end);
    } else {
      merged.push({ ...interval });
    }
  }

  let out = '';
  let cursor = left;
  for (const interval of merged) {
    out += line.slice(cursor, interval.start);
    const matched = line.slice(interval.start, interval.end);
    out += matched.length <= 4
      ? '*'.repeat(matched.length)
      : matched.slice(0, 2) + '*'.repeat(Math.max(0, matched.length - 4)) + matched.slice(-2);
    cursor = interval.end;
  }
  out += line.slice(cursor, right);

  const prefix = left === 0 ? '' : '…';
  const suffix = right === line.length ? '' : '…';
  return `${prefix}${out}${suffix}`;
}

// ── Service-key patterns shared with apiKeyDetector ──────────────────────────
const SERVICE_KEY_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'Stripe Live Key', pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
  { name: 'Stripe Test Key', pattern: /\bsk_test_[0-9a-zA-Z]{24,}\b/g },
  { name: 'GitHub Token', pattern: /\bgh[psou]_[A-Za-z0-9]{36,}\b/g },
  { name: 'Firebase Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'SendGrid Key', pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g },
  { name: 'Twilio SID', pattern: /\bAC[a-f0-9]{32}\b/g },
];

// ── Rules ────────────────────────────────────────────────────────────────────

/**
 * Identifies the card brand from a BIN (Bank Identification Number).
 * Returns null when no brand pattern matches — caller should NOT flag the digit run as
 * a PAN. This is the precision lever that distinguishes a real PAN from a Luhn-valid
 * timestamp / correlation id / phone number.
 *
 * Ranges sourced from ISO/IEC 7812 issuer registry and major brand spec documents.
 */
export function identifyCardBrand(digits: string): string | null {
  const len = digits.length;
  if (len < 13 || len > 19) return null;
  const d = digits;
  // Amex: 34, 37; length 15.
  if (len === 15 && (d.startsWith('34') || d.startsWith('37'))) return 'AMEX';
  // Visa: 4; length 13, 16, or 19.
  if ((len === 13 || len === 16 || len === 19) && d[0] === '4') return 'VISA';
  // Mastercard: 51-55 or 2221-2720; length 16.
  if (len === 16) {
    if (d[0] === '5' && d[1] >= '1' && d[1] <= '5') return 'MASTERCARD';
    const prefix4 = parseInt(d.slice(0, 4), 10);
    if (prefix4 >= 2221 && prefix4 <= 2720) return 'MASTERCARD';
  }
  // Discover: 6011, 622126-622925, 644-649, 65; length 16 or 19.
  if (len === 16 || len === 19) {
    if (d.startsWith('6011')) return 'DISCOVER';
    if (d.startsWith('65')) return 'DISCOVER';
    const prefix3 = parseInt(d.slice(0, 3), 10);
    if (prefix3 >= 644 && prefix3 <= 649) return 'DISCOVER';
    const prefix6 = parseInt(d.slice(0, 6), 10);
    if (prefix6 >= 622126 && prefix6 <= 622925) return 'DISCOVER';
  }
  // JCB: 3528-3589; length 16 or 19.
  if (len === 16 || len === 19) {
    const prefix4 = parseInt(d.slice(0, 4), 10);
    if (prefix4 >= 3528 && prefix4 <= 3589) return 'JCB';
  }
  // Diners Club: 300-305, 36, 38; length 14.
  if (len === 14) {
    const prefix3 = parseInt(d.slice(0, 3), 10);
    if (prefix3 >= 300 && prefix3 <= 305) return 'DINERS';
    if (d.startsWith('36') || d.startsWith('38')) return 'DINERS';
  }
  // UnionPay: 62; length 16 or 19. Major issuer for UAE-resident Chinese tourists.
  if ((len === 16 || len === 19) && d.startsWith('62')) return 'UNIONPAY';
  return null;
}

/** LOG-PCI-001: PAN with Luhn validation AND BIN-prefix brand identification. */
export const ruleLogPan: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Match digit-runs (with optional separators) of 13-19 digits. Wide outer net,
  // then the brand + Luhn gates inside.
  const pattern = /(?:\d[ -]?){13,19}/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    const raw = match[0];
    const digits = raw.replace(/[\s-]/g, '');
    if (digits.length < 13 || digits.length > 19) continue;
    if (!passesLuhn(digits)) continue;
    const brand = identifyCardBrand(digits);
    if (!brand) continue;
    out.push({
      ruleId: 'LOG-PCI-001',
      title: `Primary Account Number (PAN) in log message — ${brand}`,
      description: `A ${digits.length}-digit Luhn-valid ${brand} PAN appears in this log line.`,
      recommendation: 'Mask PAN at the application layer (PCI-DSS 3.3 allows first 6 + last 4 max).',
      severity: 'CRITICAL',
      category: 'LOG_PCI',
      start: match.index,
      end: match.index + raw.length,
      match: digits,
    });
  }
  return out;
};

/** LOG-PCI-002: CVV near a card context or labelled with cvv=. */
export const ruleLogCvv: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Labelled CVV/CVC/CSC with a 3-4 digit value. The `"?` after the keyword handles
  // JSON shapes like `"cvv": "123"` where a closing quote sits between the key and `:`.
  const labelled = /\b(?:cvv|cvc|csc|card[_-]?verification)"?\s*[:=]\s*"?(\d{3,4})\b/gi;
  let match: RegExpExecArray | null;
  while ((match = labelled.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-PCI-002',
      title: 'Card Verification Value (CVV/CVC) in log message',
      description: 'A CVV/CVC label with a 3-4 digit value appears in this log line. PCI-DSS Req 3.2 prohibits storing CVV post-auth.',
      recommendation: 'Strip CVV at the request boundary; rotate affected accounts.',
      severity: 'CRITICAL',
      category: 'LOG_PCI',
      start: match.index,
      end: match.index + match[0].length,
      match: match[1],
    });
  }
  return out;
};

/** LOG-PCI-003: Track 1 / Track 2 magnetic stripe data. */
export const ruleLogTrackData: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Track 1: %B<PAN>^<NAME>^<expiry/service code>?<discretionary>?
  // Track 2: ;<PAN>=<expiry/service code><discretionary>?
  const t1 = /%B\d{12,19}\^[^^]{2,26}\^\d{4,}\?/g;
  const t2 = /;\d{12,19}=\d{4,}\?/g;
  for (const pattern of [t1, t2]) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(line)) !== null) {
      out.push({
        ruleId: 'LOG-PCI-003',
        title: 'Magnetic Stripe Track Data in log message',
        description: 'A magnetic-stripe track signature appears in this log line. Storing track data is prohibited by PCI-DSS under any condition.',
        recommendation: 'Treat the log volume as a breach and notify the acquirer per PCI-DSS Req 12.10.',
        severity: 'CRITICAL',
        category: 'LOG_PCI',
        start: match.index,
        end: match.index + match[0].length,
        match: match[0],
      });
    }
  }
  return out;
};

/** LOG-PII-001: UAE Emirates ID (784-YYYY-XXXXXXX-X). */
export const ruleLogEmiratesId: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Accept hyphens or no separators.
  const pattern = /\b784[- ]?(\d{4})[- ]?\d{7}[- ]?\d\b/g;
  let match: RegExpExecArray | null;
  const currentYear = new Date().getFullYear();
  while ((match = pattern.exec(line)) !== null) {
    const year = parseInt(match[1], 10);
    if (year < 1900 || year > currentYear) continue;
    out.push({
      ruleId: 'LOG-PII-001',
      title: 'UAE Emirates ID in log message',
      description: `An Emirates ID (year ${year}) appears in this log line.`,
      recommendation: 'Hash or pseudonymise the Emirates ID before logging. UAE PDPL Article 24.',
      severity: 'HIGH',
      category: 'LOG_PII',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-PII-002: IBAN (mod-97). */
export const ruleLogIban: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // ISO 13616 IBANs: 2-letter country + 2 check digits + 11-30 alphanumeric.
  const pattern = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    if (!passesIbanMod97(match[0])) continue;
    out.push({
      ruleId: 'LOG-PII-002',
      title: 'IBAN in log message',
      description: `A valid IBAN (${match[0].slice(0, 2)} country) appears in this log line.`,
      recommendation: 'Mask all but last 4 of IBAN before logging.',
      severity: 'HIGH',
      category: 'LOG_PII',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-PII-003: Email. */
export const ruleLogEmail: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-PII-003',
      title: 'Email address in log message (potentially identifying customer)',
      description: 'A syntactically valid email address appears in this log line.',
      recommendation: 'Hash or domain-mask customer emails.',
      severity: 'MEDIUM',
      category: 'LOG_PII',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-PII-004: UAE phone numbers. */
export const ruleLogUaePhone: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // +971 + 5X + 7 digits, or 05X + 7 digits.
  const pattern = /(?:\+971[- ]?|00971[- ]?|0)(?:50|52|54|55|56|58)[- ]?\d{7}\b/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-PII-004',
      title: 'UAE phone number in log message',
      description: 'A UAE-formatted mobile number appears in this log line.',
      recommendation: 'Mask the local portion of customer phone numbers.',
      severity: 'MEDIUM',
      category: 'LOG_PII',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-PII-005: Passport number — heuristic, broad. */
export const ruleLogPassport: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Must be in a context like "passport=" or "passportNumber:" — bare matches are too noisy.
  const pattern = /\b(?:passport(?:[_-]?(?:no|number|id))?)\s*[:=]\s*"?([A-Z][0-9A-Z]{6,9})\b/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-PII-005',
      title: 'Passport number pattern in log message',
      description: 'A `passport=`-labelled value matching the international passport-number shape appears in this log line.',
      recommendation: 'Never log passport numbers in plaintext.',
      severity: 'HIGH',
      category: 'LOG_PII',
      start: match.index,
      end: match.index + match[0].length,
      match: match[1],
    });
  }
  return out;
};

/** LOG-SEC-001: Plaintext password. */
export const ruleLogPlaintextPassword: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Match key=value where key is password/pwd/passwd, value is non-trivial.
  // Reject masked values (****), placeholders ([REDACTED]), short tokens (<5 chars).
  const pattern = /\b(password|passwd|pwd|userPassword)\s*[:=]\s*("([^"\\]{6,})"|'([^'\\]{6,})'|([^\s,;)]+))/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    const value = match[3] ?? match[4] ?? match[5] ?? '';
    if (value.length < 5) continue;
    if (/^\*+$/.test(value)) continue;
    if (/^\[?(redacted|masked|hidden|null|undefined|none)\]?$/i.test(value)) continue;
    out.push({
      ruleId: 'LOG-SEC-001',
      title: 'Plaintext password in log message',
      description: 'A `password=` field with a non-trivial value appears in this log line.',
      recommendation: 'Strip password fields at the request boundary; rotate any retained credentials.',
      severity: 'CRITICAL',
      category: 'LOG_SECRET',
      start: match.index,
      end: match.index + match[0].length,
      match: value,
    });
  }
  return out;
};

/** LOG-SEC-002: Bearer or JWT. */
export const ruleLogBearerOrJwt: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const bearer = /\bBearer\s+([A-Za-z0-9._\-/+=]{20,})/g;
  // JWT: header.payload.signature. Header & payload start with `eyJ` and contain
  // base64url bytes; signature length varies (≥6 catches HS256 truncated test tokens
  // and all real-world signatures).
  const jwt = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}\b/g;
  for (const pattern of [bearer, jwt]) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(line)) !== null) {
      out.push({
        ruleId: 'LOG-SEC-002',
        title: 'Bearer token or JWT in log message',
        description: 'A Bearer or JWT credential appears in this log line.',
        recommendation: 'Redact Authorization headers in the logging middleware; revoke exposed tokens.',
        severity: 'CRITICAL',
        category: 'LOG_SECRET',
        start: match.index,
        end: match.index + match[0].length,
        match: match[1] ?? match[0],
      });
    }
  }
  return out;
};

/** LOG-SEC-003: Service API key in log. */
export const ruleLogServiceApiKey: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  for (const { name, pattern } of SERVICE_KEY_PATTERNS) {
    const fresh = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = fresh.exec(line)) !== null) {
      out.push({
        ruleId: 'LOG-SEC-003',
        title: 'Service API key in log message',
        description: `A ${name} pattern appears in this log line.`,
        recommendation: 'Rotate the exposed key; add a redaction filter to the logger.',
        severity: 'CRITICAL',
        category: 'LOG_SECRET',
        start: match.index,
        end: match.index + match[0].length,
        match: match[0],
      });
    }
  }
  return out;
};

/** LOG-SEC-004: PEM private key. */
export const ruleLogPrivateKey: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-SEC-004',
      title: 'Private key block in log message',
      description: 'A PEM private-key block appears in this log line.',
      recommendation: 'Rotate the exposed key; audit how it reached the logger.',
      severity: 'CRITICAL',
      category: 'LOG_SECRET',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-OPS-001: DB connection error revealing creds. */
export const ruleLogDbConnError: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // mongodb://user:pass@host, postgres://user:pass@host, mysql://, etc.
  const pattern = /\b(?:mongodb|postgres(?:ql)?|mysql|mariadb|amqp|redis|rediss?|kafka):\/\/[^:\/\s]+:[^@\/\s]+@[^\s,)]+/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-OPS-001',
      title: 'Database connection error revealing credentials in log',
      description: 'A connection-string-with-credentials pattern appears in this log line.',
      recommendation: 'Strip credentials from connection-failure logs; rotate the exposed credential.',
      severity: 'HIGH',
      category: 'LOG_OPS',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-PCI-004: URL-encoded PAN — `%34%32%34%32...` reaches the same risk. */
export const ruleLogUrlEncodedPan: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // URL-encoded digits look like `%3X` where X is hex 0-9 (for ASCII '0'-'9').
  // We try to decode any run of 24+ chars matching `%3[0-9]` repeated and check Luhn.
  const pattern = /(?:%3[0-9]){13,19}/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    const decoded = match[0].replace(/%3([0-9])/gi, '$1');
    if (!passesLuhn(decoded)) continue;
    const brand = identifyCardBrand(decoded);
    if (!brand) continue;
    out.push({
      ruleId: 'LOG-PCI-001',
      title: `Primary Account Number (PAN) in log message — ${brand} (URL-encoded)`,
      description: `A URL-encoded ${decoded.length}-digit ${brand} PAN appears in this log line.`,
      recommendation: 'Mask PAN before logging; URL-encoding is not redaction. PCI-DSS 3.3.',
      severity: 'CRITICAL',
      category: 'LOG_PCI',
      start: match.index,
      end: match.index + match[0].length,
      match: decoded,
    });
  }
  return out;
};

/** LOG-SEC-005: Env-var-style password disclosure (DB_PASS=..., MYSQL_PWD=...). */
export const ruleLogEnvVarPassword: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Common env-var naming patterns banks use for secrets.
  const pattern = /\b([A-Z][A-Z0-9_]{1,40}(?:PASSWORD|PASSWD|PWD|SECRET|KEY|TOKEN))=([^\s,;'"]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    const value = match[2];
    if (value.length < 6) continue;
    if (/^\*+$/.test(value)) continue;
    if (/^\[?(redacted|masked|hidden|null|undefined|none)\]?$/i.test(value)) continue;
    // Skip dotenv-style file paths (`KEY=path/to/key.pem`).
    if (/^\.{0,2}\/[^,;'"]+/.test(value)) continue;
    out.push({
      ruleId: 'LOG-SEC-001',
      title: 'Plaintext password in log message',
      description: `Environment-variable-style secret \`${match[1]}=\` with a non-trivial value appears in this log line.`,
      recommendation: 'Strip environment dumps from process startup logs; rotate retained credentials.',
      severity: 'CRITICAL',
      category: 'LOG_SECRET',
      start: match.index,
      end: match.index + match[0].length,
      match: value,
    });
  }
  return out;
};

/** LOG-SEC-006: AWS session token (40-char base64-ish) — usually appears with KEY/SECRET context. */
export const ruleLogAwsSessionToken: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // AWS session tokens are typically 240-400+ chars, start with `Fwo` or `IQo` for SigV4.
  const pattern = /\b(?:FwoGZXIvYXdz|IQoJb3JpZ2luX2VjE)[A-Za-z0-9+/=]{40,}\b/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-SEC-003',
      title: 'AWS session token in log message',
      description: 'An AWS STS session token (SigV4 shape) appears in this log line.',
      recommendation: 'Rotate the assumed-role credentials immediately; add redaction to the request logger.',
      severity: 'CRITICAL',
      category: 'LOG_SECRET',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

/** LOG-OPS-002: Stack trace path with sensitive directory name. */
export const ruleLogSensitiveStackPath: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /(?:\/[^\s:]*\/(?:secrets|keys|vault|credentials|private)\/[^\s:]+)/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(line)) !== null) {
    out.push({
      ruleId: 'LOG-OPS-002',
      title: 'Stack trace containing sensitive file path',
      description: `A path containing a sensitive-directory token appears in this log line.`,
      recommendation: 'Use a structured logger that strips file paths or maps them to safe identifiers.',
      severity: 'LOW',
      category: 'LOG_OPS',
      start: match.index,
      end: match.index + match[0].length,
      match: match[0],
    });
  }
  return out;
};

export const ALL_LOG_RULES: LogRule[] = [
  ruleLogPan,
  ruleLogUrlEncodedPan,
  ruleLogCvv,
  ruleLogTrackData,
  ruleLogEmiratesId,
  ruleLogIban,
  ruleLogEmail,
  ruleLogUaePhone,
  ruleLogPassport,
  ruleLogPlaintextPassword,
  ruleLogEnvVarPassword,
  ruleLogBearerOrJwt,
  ruleLogServiceApiKey,
  ruleLogAwsSessionToken,
  ruleLogPrivateKey,
  ruleLogDbConnError,
  ruleLogSensitiveStackPath,
];

/** Run every rule against a single line. */
export function scanLogLine(line: string): LogRuleMatch[] {
  const out: LogRuleMatch[] = [];
  for (const rule of ALL_LOG_RULES) {
    out.push(...rule(line));
  }
  return out;
}

/**
 * Build a Finding from a rule match + the ES hit it came from. The Finding shape matches
 * the existing code-review Finding so SARIF / baseline / threshold logic just works.
 *
 * `otherMatches` (optional) carries every other rule match on the same line so the
 * excerpt redacts ALL co-located sensitive values, not just this one. Mandatory for
 * PCI-DSS / UAE PDPL compliance — without it, Bearer/JWT findings could leak a
 * neighboring plaintext password into the excerpt.
 */
export function matchToFinding(
  match: LogRuleMatch,
  hit: LogHit,
  containerName: string,
  kibanaDeepLink: string | undefined,
  otherMatches: LogRuleMatch[] = []
): Finding {
  const excerpt = buildRedactedExcerpt(
    hit.message,
    match.start,
    match.end,
    otherMatches.filter((m) => m !== match).map((m) => ({ start: m.start, end: m.end }))
  );
  return {
    ruleId: match.ruleId,
    category: match.category,
    severity: match.severity,
    title: match.title,
    description: match.description,
    // "file" is the log location, formatted so SARIF reporting still works.
    file: `${hit._index}/${hit._id}`,
    line: 1,
    column: match.start + 1,
    // Keep the redacted excerpt as the code field — SARIF surfaces this as snippet.
    code: excerpt,
    recommendation: match.recommendation,
    logEvidence: {
      docId: hit._id,
      index: hit._index,
      timestamp: hit.timestamp,
      container: containerName,
      kibanaUrl: kibanaDeepLink,
      excerpt,
    },
  };
}
