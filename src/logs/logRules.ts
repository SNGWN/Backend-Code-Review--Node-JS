import { Finding, IssueCategory, Severity } from '../types';
import { LogHit } from './kibanaClient';

/* eslint-disable @typescript-eslint/no-explicit-any */

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
 * PCI-DSS compliant masking. PAN-shaped digit runs (13-19 digits) are masked as
 * "first 6 + middle masked + last 4" per Req 3.3, giving SOC analysts enough to
 * triage (BIN-prefix issuer ID + last 4 for customer correlation) without
 * exceeding the retention permission. Other matches use first-2 + last-2.
 */
function maskMatchedValue(matched: string): string {
  if (matched.length <= 4) return '*'.repeat(matched.length);
  const digitsOnly = matched.replace(/\D/g, '');
  if (digitsOnly.length >= 13 && digitsOnly.length <= 19) {
    // PCI-DSS first-6-last-4: keep brand prefix + last 4 for correlation.
    return matched.slice(0, 6) + '*'.repeat(Math.max(0, matched.length - 10)) + matched.slice(-4);
  }
  return matched.slice(0, 2) + '*'.repeat(Math.max(0, matched.length - 4)) + matched.slice(-2);
}

/**
 * Builds a redacted excerpt of the matched line. We keep ~40 chars of context on each
 * side but mask the matched substring. PCI-DSS Req 3.3 allows first 6 + last 4 of PAN.
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
  otherMatches: Array<{ start: number; end: number }> = [],
  /**
   * Optional field boundary `[lo, hi)`. When provided, the excerpt window is clamped so it cannot
   * straddle the primary-message / structured-`_source` boundary — keeping the snippet (and any
   * co-located masking) inside the single field the match belongs to (M30).
   */
  windowBounds?: { lo: number; hi: number }
): string {
  const lo = windowBounds ? Math.max(0, windowBounds.lo) : 0;
  const hi = windowBounds ? Math.min(line.length, windowBounds.hi) : line.length;
  const left = Math.max(lo, start - 40);
  const right = Math.min(hi, end + 40);

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
    out += maskMatchedValue(line.slice(interval.start, interval.end));
    cursor = interval.end;
  }
  out += line.slice(cursor, right);

  const prefix = left === lo ? '' : '…';
  const suffix = right === hi ? '' : '…';
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
  // Bounded, non-overlapping form. The previous `[A-Za-z0-9.-]+\.[A-Za-z]{2,}` let `.` belong to
  // both the label class and the literal dot, giving catastrophic backtracking on inputs like
  // `a@` + many letters with no final dot. Splitting the domain into discrete labels removes the
  // ambiguity (≈678ms → ≈10ms on the worst case) while still matching real multi-label emails.
  const pattern = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b/g;
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

// ── Expanded coverage (1.1) ──────────────────────────────────────────────────

/**
 * Shannon entropy in bits-per-char for a string. Used to gate generic-secret matches —
 * the value must be high-entropy (≥ 4 bits/char) before we call it a credential.
 */
function shannonEntropyBitsPerChar(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksLikePlaceholder(value: string): boolean {
  if (!value || value.length < 4) return true;
  if (/^\*+$/.test(value)) return true;
  if (/^\[?(redacted|masked|hidden|null|undefined|none|todo|fixme|example|sample)\]?$/i.test(value)) return true;
  if (/^x{3,}$/i.test(value)) return true;
  return false;
}

/** Build a match record helper. */
function buildMatch(
  ruleId: LogRuleMatch['ruleId'],
  title: string,
  description: string,
  recommendation: string,
  severity: Severity,
  category: IssueCategory,
  index: number,
  fullLength: number,
  matched: string
): LogRuleMatch {
  return {
    ruleId, title, description, recommendation, severity, category,
    start: index, end: index + fullLength, match: matched,
  };
}

/** LOG-PII-006: customer full name. */
export const ruleLogCustomerName: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(firstName|lastName|fullName|customerName|first_name|last_name|full_name|customer_name)"?\s*[:=]\s*"?([^,;'"\s]{2,}(?:[ \-][A-Z][A-Za-z]+){1,5})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const value = m[2];
    if (looksLikePlaceholder(value)) continue;
    out.push(buildMatch('LOG-PII-006', 'Customer full name in log message',
      `Customer-name field \`${m[1]}\` with multi-word value appears in this log line.`,
      'Hash, pseudonymise, or truncate customer names. UAE PDPL Article 6.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, value));
  }
  return out;
};

/** LOG-PII-007: date of birth. */
export const ruleLogDateOfBirth: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(dob|dateOfBirth|date_of_birth|birthDate|birth_date)"?\s*[:=]\s*"?(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-PII-007', 'Date of birth in log message',
      'A date-of-birth field with date value appears in this log line.',
      'Replace DoB with an age band or hash.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-PII-008: physical address (labelled, heuristic). */
export const ruleLogAddress: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(address|streetAddress|street_address|homeAddress|home_address|customer_address)"?\s*[:=]\s*"([A-Za-z0-9][A-Za-z0-9 ,.#\-/']{12,200})"/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const value = m[2];
    if (looksLikePlaceholder(value)) continue;
    if (!/\d/.test(value)) continue; // require at least one digit (street numbers / unit)
    out.push(buildMatch('LOG-PII-008', 'Physical address in log message',
      'A labelled address field with a multi-word, digit-bearing value appears in this log line.',
      'Strip address fields before logging.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, value));
  }
  return out;
};

/** LOG-ACCT-001: bank account number (labelled). */
export const ruleLogBankAccountNumber: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(account_?number|acc_?no|accountId)"?\s*[:=]\s*"?(\d{8,18})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-ACCT-001', 'Bank account number in log message',
      'A labelled bank-account-number field appears in this log line.',
      'Mask all but last 4 of account numbers. CBUAE Consumer Protection § B.4.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-ACCT-002: sort code / routing number. */
export const ruleLogSortRoutingCode: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Sort codes: 6 digits with optional dashes (e.g. 12-34-56). Routing: 9 digits.
  const pattern = /\b(sort_?code|routing_?number|aba)"?\s*[:=]\s*"?(\d{2,3}[- ]?\d{2,3}[- ]?\d{2,4}|\d{6,9})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-ACCT-002', 'Sort code / routing number in log message',
      'A labelled sort-code / routing-number field appears in this log line.',
      'Mask routing identifiers when paired with account numbers.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-ACCT-003: SWIFT / BIC code. */
export const ruleLogSwiftBic: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // SWIFT/BIC format: 4 letters bank + 2 letters country + 2 alphanumeric location + optional 3 alphanumeric branch.
  const pattern = /\b(swift|bic|swiftCode|bicCode)"?\s*[:=]\s*"?([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-ACCT-003', 'SWIFT / BIC code in log message',
      'A labelled SWIFT/BIC field with valid format appears in this log line.',
      'Mask SWIFT/BIC paired with account numbers.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-DOC-001: UAE driving license (labelled). */
export const ruleLogUaeDrivingLicense: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // UAE DL: 7-9 digit license number, prefixed by emirate code (AD/DXB/SHJ/AJM/UAQ/RAK/FUJ).
  // Most commonly logged as plain digits with a label.
  const pattern = /\b(driving_?license|driver_?license|dl_?no|dl_?number|drivingLicense)"?\s*[:=]\s*"?([A-Z]{0,3}[ -]?\d{7,9})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-DOC-001', 'UAE driving license number in log message',
      'A labelled driving-license field appears in this log line.',
      'Never log driving license numbers in plaintext. UAE PDPL Article 24.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-DOC-002: UAE visa / residence permit. */
export const ruleLogUaeVisaPermit: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Common shapes: 101/2020/3000234, AE-2020-123456, RP-12345678.
  const pattern = /\b(visa|visa_?no|residence_?permit|residency_?permit|residence_?id)"?\s*[:=]\s*"?(\d{1,3}\/\d{1,4}\/\d{4,12}|[A-Z]{1,3}[-]?\d{4,12})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-DOC-002', 'UAE visa / residence permit number in log message',
      'A labelled visa / residence-permit field appears in this log line.',
      'Never log visa numbers in plaintext.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-DOC-003: UAE Tax Registration Number (15-digit). */
export const ruleLogUaeTrn: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(trn|tax_?reg(?:istration)?_?(?:number|no))"?\s*[:=]\s*"?(\d{15})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-DOC-003', 'Tax Registration Number (TRN) in log message',
      'A labelled TRN field with 15-digit value appears in this log line.',
      'Mask TRN before logging.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-DOC-004: generic national ID. */
export const ruleLogGenericNationalId: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(national_?id|nationalId|id_?number|government_?id)"?\s*[:=]\s*"?([A-Z0-9][A-Z0-9-]{6,20})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const value = m[2];
    if (looksLikePlaceholder(value)) continue;
    // Skip if it's the UAE Emirates ID shape — already covered by LOG-PII-001.
    if (/^784/.test(value.replace(/[-]/g, ''))) continue;
    out.push(buildMatch('LOG-DOC-004', 'Generic national ID in log message',
      'A labelled national-ID field appears in this log line.',
      'Hash or pseudonymise national identifiers.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, value));
  }
  return out;
};

/** LOG-PCI-005: card expiry. */
export const ruleLogCardExpiry: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(exp|expiry|expiration|cardExpiry|card_expiry|exp_?date)"?\s*[:=]\s*"?(0[1-9]|1[0-2])[\/\-](\d{2}|\d{4})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-PCI-005', 'Card expiry date in log message',
      'A labelled card-expiry field with MM/YY or MM/YYYY value appears in this log line.',
      'Strip expiry alongside PAN. PCI-DSS Req 3.3.',
      'MEDIUM', 'LOG_PCI', m.index, m[0].length, `${m[2]}/${m[3]}`));
  }
  return out;
};

/** LOG-PCI-006: cardholder name. */
export const ruleLogCardholderName: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(cardholder|cardholderName|card_holder|holder_name)"?\s*[:=]\s*"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){1,4})"/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const value = m[2];
    if (looksLikePlaceholder(value)) continue;
    out.push(buildMatch('LOG-PCI-006', 'Cardholder name in log message',
      'A labelled cardholder-name field with multi-word value appears in this log line.',
      'PCI-DSS Req 3.4 — cardholder name + PAN must be rendered unreadable in storage.',
      'MEDIUM', 'LOG_PCI', m.index, m[0].length, value));
  }
  return out;
};

/** LOG-FIN-001: account balance. */
export const ruleLogAccountBalance: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Simplified pattern — match a digit run with optional decimal, optional currency.
  const pattern = /\b(balance|availableBalance|available_balance|current_balance|ledger_balance)"?\s*[:=]\s*"?(\d[\d,]*(?:\.\d{1,4})?)\s*"?\s*(AED|USD|EUR|GBP|SAR|JPY|INR|CNY)?/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const value = m[2];
    const currency = m[3];
    // Require either a currency or a decimal point (so we don't fire on `balance: 0`).
    if (!currency && !value.includes('.')) continue;
    if (Number(value.replace(/,/g, '')) === 0) continue;
    out.push(buildMatch('LOG-FIN-001', 'Account balance disclosed in log message',
      'A labelled balance field with a numeric value appears in this log line.',
      'Never log customer balances in plaintext. Use buckets/deciles if telemetry is required.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, value));
  }
  return out;
};

/** Public IPv4 helper — RFC 1918 / 100.64 / loopback are NOT public. */
function isPublicIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return false;
  if (a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false; // multicast / reserved
  if (a === 0) return false;
  return true;
}

/** LOG-NET-001: customer IPv4 in customer-context field. */
export const ruleLogCustomerIPv4: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(client_ip|source_ip|src_ip|remote_addr|customer_ip|user_ip|x_forwarded_for|real_ip|origin_ip)"?\s*[:=]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const ip = m[2];
    if (!isPublicIPv4(ip)) continue;
    out.push(buildMatch('LOG-NET-001', 'Customer IP address in log message',
      'A public IPv4 in a customer-context field appears in this log line.',
      'Hash customer IPs or retain only the /24.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, ip));
  }
  return out;
};

/** LOG-NET-002: IPv6 in customer context. */
export const ruleLogIPv6: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Allow `::` zero-compression (consecutive colons), variable hex segment lengths.
  const pattern = /\b(client_ip|source_ip|src_ip|remote_addr|customer_ip|user_ip|x_forwarded_for|real_ip|origin_ip)"?\s*[:=]\s*"?((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{1,4})/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const ip = m[2];
    // Exclude IPv6 loopback and link-local.
    if (ip === '::1' || /^fe80:/i.test(ip)) continue;
    out.push(buildMatch('LOG-NET-002', 'IPv6 address in customer context',
      'An IPv6 address in a customer-context field appears in this log line.',
      'Hash customer IPv6 or retain only the /48.',
      'MEDIUM', 'LOG_PII', m.index, m[0].length, ip));
  }
  return out;
};

/** LOG-NET-003: internal RFC-1918 / 100.64 IP exposure (heuristic). */
export const ruleLogInternalIp: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Any RFC-1918 / 100.64 IP appearing in a log line.
  const pattern = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-NET-003', 'Internal RFC-1918 IP address exposed in log message',
      'An RFC-1918 / 100.64 address appears in this log line.',
      'Confirm log retention boundary does not expose internal topology to third parties.',
      'LOW', 'LOG_OPS', m.index, m[0].length, m[1]));
  }
  return out;
};

/** LOG-SEC-005..007: OAuth client_id / client_secret / refresh_token. */
export const ruleLogOAuthCreds: LogRule = (line) => {
  const out: LogRuleMatch[] = [];

  // client_secret (CRITICAL)
  const secretPattern = /\b(client[_-]?secret)"?\s*[:=]\s*"?([^\s,;'"]{8,})/gi;
  let m: RegExpExecArray | null;
  while ((m = secretPattern.exec(line)) !== null) {
    if (looksLikePlaceholder(m[2])) continue;
    out.push(buildMatch('LOG-SEC-005', 'OAuth client_secret in log message',
      'A labelled `client_secret=` field with a non-trivial value appears in this log line.',
      'Rotate the OAuth client secret.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[2]));
  }

  // client_id (MEDIUM)
  const idPattern = /\b(client[_-]?id)"?\s*[:=]\s*"?([A-Za-z0-9._\-]{8,})/gi;
  while ((m = idPattern.exec(line)) !== null) {
    if (looksLikePlaceholder(m[2])) continue;
    out.push(buildMatch('LOG-SEC-006', 'OAuth client_id in log message',
      'A labelled `client_id=` field with a non-trivial value appears in this log line.',
      'Confirm the corresponding client_secret has not also leaked.',
      'MEDIUM', 'LOG_SECRET', m.index, m[0].length, m[2]));
  }

  // refresh_token (CRITICAL)
  const refreshPattern = /\b(refresh[_-]?token)"?\s*[:=]\s*"?([A-Za-z0-9._\-/+=]{16,})/gi;
  while ((m = refreshPattern.exec(line)) !== null) {
    if (looksLikePlaceholder(m[2])) continue;
    out.push(buildMatch('LOG-SEC-007', 'Refresh token in log message',
      'A labelled `refresh_token=` field with a non-trivial value appears in this log line.',
      'Revoke the leaked refresh token.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[2]));
  }

  return out;
};

/** LOG-SEC-008: session token. */
export const ruleLogSessionToken: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(session[_-]?token|sessionId|session_id|sid|jsessionid|phpsessid)"?\s*[:=]\s*"?([A-Za-z0-9._\-/+=]{12,})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    if (looksLikePlaceholder(m[2])) continue;
    out.push(buildMatch('LOG-SEC-008', 'Session token in log message',
      'A labelled session-token field with a session-shaped value appears in this log line.',
      'Invalidate sessions appearing in log volumes.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-SEC-009: CSRF / XSRF token. */
export const ruleLogCsrfToken: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(csrf[_-]?token|xsrf[_-]?token|_csrf|anti[_-]?forgery)"?\s*[:=]\s*"?([A-Za-z0-9._\-/+=]{16,})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    if (looksLikePlaceholder(m[2])) continue;
    out.push(buildMatch('LOG-SEC-009', 'CSRF / XSRF token in log message',
      'A labelled CSRF/XSRF token field appears in this log line.',
      'CSRF tokens are session-scoped — leaked tokens enable forged-request chains.',
      'HIGH', 'LOG_SECRET', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-SEC-010: SSH key (public or private). */
export const ruleLogSshKey: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Real SSH keys are hundreds of chars; we set the threshold low enough to catch
  // truncated copies that still expose the key prefix shape.
  const pattern = /\b(ssh-(?:rsa|dss|ed25519|ecdsa-sha2-nistp(?:256|384|521)))\s+[A-Za-z0-9+/]{40,}={0,2}/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-SEC-010', 'SSH public/private key block in log message',
      'An OpenSSH-format key block appears in this log line.',
      'Confirm whether the key was customer-context or server-context. Rotate if private.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[0]));
  }
  return out;
};

/** LOG-SEC-011: Azure SAS token. */
export const ruleLogAzureSas: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Match `?sv=YYYY-MM-DD…&sig=…`. Allow any URL params between `sv` and `sig`.
  const pattern = /\?sv=\d{4}-\d{2}-\d{2}[^\s"']*?&sig=[A-Za-z0-9%+/=_-]{10,}/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-SEC-011', 'Azure SAS token in log message',
      'An Azure Shared Access Signature appears in this log line.',
      'Rotate the SAS token; reduce TTL and scope of new tokens.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[0]));
  }
  return out;
};

/** LOG-SEC-012: GCP service account JSON. */
export const ruleLogGcpServiceAccount: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Look for the type+private_key combination on the same line (JSON would normally
  // line-feed but log shippers often collapse to one line).
  const pattern = /"type"\s*:\s*"service_account"[^]{1,400}?"private_key"\s*:\s*"-----BEGIN/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-SEC-012', 'GCP service account JSON in log message',
      'A GCP service-account JSON appears in this log line.',
      'Disable the service account key immediately; rotate.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[0]));
  }
  return out;
};

/** LOG-SEC-013: public / API / access token (labelled). */
export const ruleLogPublicOrApiToken: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(public[_-]?token|api[_-]?token|access[_-]?token|app[_-]?token|integration[_-]?token)"?\s*[:=]\s*"?([A-Za-z0-9._\-/+=]{16,})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    if (looksLikePlaceholder(m[2])) continue;
    out.push(buildMatch('LOG-SEC-013', 'Public token / API token in log message',
      'A labelled token field with a non-trivial value appears in this log line.',
      'Revoke the leaked token.',
      'HIGH', 'LOG_SECRET', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-SEC-014: generic high-entropy *_secret= / *_key= / *_token= */
export const ruleLogGenericHighEntropySecret: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b([A-Za-z][A-Za-z0-9_-]{1,40}(?:secret|key|token|password|credential))"?\s*[:=]\s*"?([A-Za-z0-9._\-/+=]{24,})/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    const labelKey = m[1].toLowerCase();
    // Skip labels already covered by tighter rules to avoid double-reporting.
    if (/(jwt|bearer|access[_-]?token|refresh[_-]?token|public[_-]?token|api[_-]?token|client[_-]?secret|client[_-]?id|cardholder|expiry|password|passwd|pwd|csrf|xsrf|session|sid)/.test(labelKey)) continue;
    const value = m[2];
    if (looksLikePlaceholder(value)) continue;
    if (shannonEntropyBitsPerChar(value) < 3.6) continue;
    out.push(buildMatch('LOG-SEC-014', 'Generic high-entropy secret in log message',
      `A labelled \`${m[1]}=\` field carrying a high-entropy value appears in this log line.`,
      'Rotate the exposed credential; add a redaction filter to the code path that logged it.',
      'HIGH', 'LOG_SECRET', m.index, m[0].length, value));
  }
  return out;
};

// ── Coverage expansion (1.2) ─────────────────────────────────────────────────

/** LOG-SEC-015: HTTP Basic-auth header `Authorization: Basic <base64>`. */
export const ruleLogBasicAuth: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\bAuthorization\s*[:=]\s*"?Basic\s+([A-Za-z0-9+/=]{16,})/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-SEC-002', 'Bearer token or JWT in log message',
      'An `Authorization: Basic …` header appears in this log line; base64-decoded value is `user:password`.',
      'Strip Authorization headers in the logging middleware; rotate exposed credentials.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[1]));
  }
  return out;
};

/** LOG-SEC-016: Slack / Discord / MS Teams webhook URLs. */
export const ruleLogWebhookUrls: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const patterns: Array<{ name: string; pattern: RegExp }> = [
    { name: 'Slack', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g },
    { name: 'Discord', pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]{24,}/g },
    { name: 'MS Teams', pattern: /https:\/\/[^\s"']+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]+@[a-f0-9-]+\/IncomingWebhook\/[A-Za-z0-9]+/g },
  ];
  for (const { name, pattern } of patterns) {
    const fresh = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = fresh.exec(line)) !== null) {
      out.push(buildMatch('LOG-SEC-003', `${name} webhook URL in log message`,
        `A ${name} incoming-webhook URL appears in this log line.`,
        `Rotate the webhook and configure a Slack/Discord/Teams App secret instead.`,
        'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[0]));
    }
  }
  return out;
};

/** LOG-SEC-017: GitHub fine-grained PATs + npm tokens (additions to service-key set). */
export const ruleLogServiceKeysExtra: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const patterns: Array<{ name: string; pattern: RegExp }> = [
    { name: 'GitHub fine-grained PAT', pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g },
    { name: 'npm token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { name: 'OpenAI key', pattern: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/g },
    { name: 'Heroku API key', pattern: /\bhe[ks]u_[A-Za-z0-9_-]{36,}\b/g },
  ];
  for (const { name, pattern } of patterns) {
    const fresh = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = fresh.exec(line)) !== null) {
      out.push(buildMatch('LOG-SEC-003', `${name} in log message`,
        `A ${name} pattern appears in this log line.`,
        `Rotate the key; add a redaction filter to the logger.`,
        'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[0]));
    }
  }
  return out;
};

/** LOG-SEC-018: AWS / GCP / Cloudflare presigned URLs. */
export const ruleLogPresignedUrl: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // AWS S3 SigV4 presigned URL signatures
  const patterns: RegExp[] = [
    /X-Amz-Signature=[A-Fa-f0-9]{32,}/g,
    /X-Goog-Signature=[A-Fa-f0-9]{32,}/g,
    /\bsig=[A-Za-z0-9%+/=_-]{20,}&se=\d/g,
  ];
  for (const pattern of patterns) {
    const fresh = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = fresh.exec(line)) !== null) {
      out.push(buildMatch('LOG-SEC-003', 'Cloud-storage presigned URL in log message',
        'A cloud-storage signed URL (S3 / GCS / Azure / Cloudflare) appears in this log line.',
        'Presigned URLs grant scoped access until expiry — rotate or invalidate by changing the underlying secret/key.',
        'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[0]));
    }
  }
  return out;
};

/** LOG-PII-011: UK National Insurance Number. */
export const ruleLogUkNi: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-PII-009', 'UK National Insurance number in log message',
      'A UK NI-shaped value appears in this log line.',
      'Mask UK NI numbers; HMRC retention rules apply.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[0]));
  }
  return out;
};

/** LOG-PII-012: Pakistani CNIC. */
export const ruleLogPakistaniCnic: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b\d{5}-\d{7}-\d\b/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-PII-009', 'Pakistani CNIC in log message',
      'A CNIC-shaped value appears in this log line.',
      'Mask CNIC; NADRA classifies as sensitive personal data.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[0]));
  }
  return out;
};

/** LOG-PII-013: Indian Aadhaar (labelled; bare 12-digit too noisy). */
export const ruleLogIndianAadhaar: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  const pattern = /\b(aadhaar|aadhar|uidai)"?\s*[:=]\s*"?(\d{4}[ -]?\d{4}[ -]?\d{4})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-PII-009', 'Indian Aadhaar in log message',
      'A labelled Aadhaar field appears in this log line.',
      'UIDAI prohibits logging Aadhaar. Mask all but last 4.',
      'HIGH', 'LOG_PII', m.index, m[0].length, m[2]));
  }
  return out;
};

/** LOG-PII-009: US Social Security Number. */
export const ruleLogUsSsn: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Valid SSN: area 001-665 or 667-899 (skip 666, 000, 9xx); group 01-99; serial 0001-9999.
  const pattern = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    out.push(buildMatch('LOG-PII-009', 'US Social Security Number in log message',
      'A pattern matching the US SSN format with area/group/serial sanity appears in this log line.',
      'Strip SSN at the request boundary. Required by GLBA, HIPAA, and many state laws.',
      'CRITICAL', 'LOG_PII', m.index, m[0].length, m[0]));
  }
  return out;
};

/** LOG-PII-010: PEM-body-only private key (header stripped by log shipper). */
export const ruleLogPemPrivateKeyBody: LogRule = (line) => {
  const out: LogRuleMatch[] = [];
  // Labelled `private_key=` / `key=` with a long base64 body. PEM bodies start with
  // `MII…` which is the DER SEQUENCE/INTEGER tag in base64.
  const pattern = /\b(private[_-]?key|pkcs8|rsa[_-]?key|signing[_-]?key)"?\s*[:=]\s*"?(MII[A-Za-z0-9+/=]{600,})/g;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(line)) !== null) {
    if (shannonEntropyBitsPerChar(m[2]) < 5.0) continue;
    out.push(buildMatch('LOG-SEC-004', 'Private key block in log message',
      'A labelled key field with a PKCS#8/PEM-body-shaped value appears in this log line.',
      'Rotate the key; investigate the path that emitted it.',
      'CRITICAL', 'LOG_SECRET', m.index, m[0].length, m[2]));
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
  // ── Expanded coverage ─────────────────────────────────────────────────
  ruleLogCustomerName,
  ruleLogDateOfBirth,
  ruleLogAddress,
  ruleLogBankAccountNumber,
  ruleLogSortRoutingCode,
  ruleLogSwiftBic,
  ruleLogUaeDrivingLicense,
  ruleLogUaeVisaPermit,
  ruleLogUaeTrn,
  ruleLogGenericNationalId,
  ruleLogCardExpiry,
  ruleLogCardholderName,
  ruleLogAccountBalance,
  ruleLogCustomerIPv4,
  ruleLogIPv6,
  ruleLogInternalIp,
  ruleLogOAuthCreds,
  ruleLogSessionToken,
  ruleLogCsrfToken,
  ruleLogSshKey,
  ruleLogAzureSas,
  ruleLogGcpServiceAccount,
  ruleLogPublicOrApiToken,
  ruleLogGenericHighEntropySecret,
  // ── 1.2 expansion ────────────────────────────────────────────────────
  ruleLogBasicAuth,
  ruleLogWebhookUrls,
  ruleLogServiceKeysExtra,
  ruleLogPresignedUrl,
  ruleLogUsSsn,
  ruleLogPemPrivateKeyBody,
  ruleLogUkNi,
  ruleLogPakistaniCnic,
  ruleLogIndianAadhaar,
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
  // `resolveMessage` appends a stringified `_source` projection after the primary message so rules
  // can scan nested fields. Clamp the excerpt window — and report the column — relative to the
  // field the match actually landed in, so a structured-region hit isn't reported at a column that
  // doesn't exist in Kibana's `message` field (M30).
  const primaryLength = typeof hit.messageFieldLength === 'number' ? hit.messageFieldLength : hit.message.length;
  const inStructured = match.start >= primaryLength && primaryLength < hit.message.length;
  // Field window: primary is `[0, primaryLength)`; structured is `[primaryLength+1, end)` (the +1
  // skips the single `\n` delimiter resolveMessage inserts between the two parts).
  const windowBounds = inStructured
    ? { lo: primaryLength + 1, hi: hit.message.length }
    : { lo: 0, hi: primaryLength };
  const excerpt = buildRedactedExcerpt(
    hit.message,
    match.start,
    match.end,
    otherMatches.filter((m) => m !== match).map((m) => ({ start: m.start, end: m.end })),
    windowBounds
  );
  // Column is 1-based within its field. For a structured-region match, that's the offset past the
  // boundary; the `_source` prefix on the snippet tells the reviewer it's a nested field, not the
  // Kibana `message` line.
  const column = inStructured ? match.start - (primaryLength + 1) + 1 : match.start + 1;
  const labeledExcerpt = inStructured ? `[_source] ${excerpt}` : excerpt;
  return {
    ruleId: match.ruleId,
    category: match.category,
    severity: match.severity,
    title: match.title,
    description: match.description,
    // "file" is the log location, formatted so SARIF reporting still works.
    file: `${hit._index}/${hit._id}`,
    line: 1,
    column: Math.max(1, column),
    // Keep the redacted excerpt as the code field — SARIF surfaces this as snippet.
    code: labeledExcerpt,
    recommendation: match.recommendation,
    logEvidence: {
      docId: hit._id,
      index: hit._index,
      timestamp: hit.timestamp,
      container: containerName,
      kibanaUrl: kibanaDeepLink,
      excerpt: labeledExcerpt,
    },
  };
}
