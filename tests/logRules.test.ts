/**
 * Log-rule precision tests.
 *
 * UAE bank context: a false positive on PAN/IBAN/Emirates ID wastes audit time and
 * undermines trust in the tool; a false negative on PAN is a PCI-DSS reportable event.
 * These tests pin both directions for every PCI/PII rule.
 */
import {
  passesLuhn,
  passesIbanMod97,
  buildRedactedExcerpt,
  scanLogLine,
  ruleLogPan,
  ruleLogIban,
  ruleLogEmiratesId,
  ruleLogCvv,
  ruleLogPlaintextPassword,
  ruleLogBearerOrJwt,
  ruleLogServiceApiKey,
  ruleLogPrivateKey,
  ruleLogDbConnError,
  ruleLogUaePhone,
} from '../src/logs/logRules';

describe('Luhn checksum', () => {
  test('accepts canonical valid test PANs', () => {
    // These are the published Visa/MC/Amex test PANs — Luhn-valid by construction.
    expect(passesLuhn('4242424242424242')).toBe(true);
    expect(passesLuhn('4111111111111111')).toBe(true);
    expect(passesLuhn('5555555555554444')).toBe(true);
    expect(passesLuhn('378282246310005')).toBe(true); // 15-digit Amex
  });

  test('rejects similar-shaped digit runs that fail Luhn', () => {
    expect(passesLuhn('4242424242424243')).toBe(false);
    expect(passesLuhn('1234567890123456')).toBe(false);
    expect(passesLuhn('9999999999999999')).toBe(false);
  });

  test('rejects too-short / non-digit input', () => {
    expect(passesLuhn('42')).toBe(false);
    expect(passesLuhn('4242-4242-4242-4242')).toBe(false); // helper rejects non-digits; caller strips
  });
});

describe('IBAN mod-97', () => {
  test('accepts canonical valid IBANs', () => {
    expect(passesIbanMod97('AE070331234567890123456')).toBe(true); // UAE example
    expect(passesIbanMod97('GB29NWBK60161331926819')).toBe(true);
    expect(passesIbanMod97('DE89370400440532013000')).toBe(true);
  });

  test('rejects single-digit-flip mutations', () => {
    expect(passesIbanMod97('GB29NWBK60161331926820')).toBe(false);
    expect(passesIbanMod97('AE070331234567890123457')).toBe(false);
  });

  test('rejects malformed strings', () => {
    expect(passesIbanMod97('GB29NWBK')).toBe(false);
    expect(passesIbanMod97('1234567890123456')).toBe(false);
  });
});

describe('PAN rule (LOG-PCI-001)', () => {
  test('fires on a Luhn-valid PAN in a log line', () => {
    const matches = ruleLogPan('customer payment failed for card 4242424242424242');
    expect(matches.length).toBe(1);
    expect(matches[0].ruleId).toBe('LOG-PCI-001');
  });

  test('does NOT fire on non-PAN 16-digit timestamps', () => {
    // ISO-week-and-millis style numeric: not Luhn-valid AND starts with 2 (out of PAN range).
    expect(ruleLogPan('correlation 2025070512345678').length).toBe(0);
  });

  test('does NOT fire on phone numbers', () => {
    expect(ruleLogPan('user phone 971501234567').length).toBe(0);
  });
});

describe('CVV rule (LOG-PCI-002)', () => {
  test('fires on cvv= label', () => {
    expect(ruleLogCvv('payload {"cvv": "123"}').length).toBe(1);
    expect(ruleLogCvv('cvc=4242').length).toBe(1);
  });

  test('does NOT fire on bare 3-digit values', () => {
    expect(ruleLogCvv('HTTP 200 OK status code').length).toBe(0);
  });
});

describe('Emirates ID rule (LOG-PII-001)', () => {
  test('fires on a properly-formatted Emirates ID', () => {
    expect(ruleLogEmiratesId('customer 784-1990-1234567-8 logged in').length).toBe(1);
    expect(ruleLogEmiratesId('id=784199012345678').length).toBe(1);
  });

  test('does NOT fire on patterns that fail the year-range sanity', () => {
    expect(ruleLogEmiratesId('784-9999-1234567-8').length).toBe(0);
  });
});

describe('IBAN rule (LOG-PII-002)', () => {
  test('fires only when mod-97 passes', () => {
    expect(ruleLogIban('transfer to GB29NWBK60161331926819 booked').length).toBe(1);
    // single-digit flip → no fire
    expect(ruleLogIban('transfer to GB29NWBK60161331926820 booked').length).toBe(0);
  });
});

describe('UAE phone rule (LOG-PII-004)', () => {
  test('fires on +971-prefix and 05X local', () => {
    expect(ruleLogUaePhone('caller +971501234567 requested OTP').length).toBe(1);
    expect(ruleLogUaePhone('contact 0501234567').length).toBe(1);
  });

  test('does NOT fire on non-UAE numbers', () => {
    expect(ruleLogUaePhone('call +14155551234').length).toBe(0);
  });
});

describe('Plaintext password rule (LOG-SEC-001)', () => {
  test('fires on password= field', () => {
    expect(ruleLogPlaintextPassword('login attempt password=S3cret!').length).toBe(1);
  });

  test('does NOT fire on masked values', () => {
    expect(ruleLogPlaintextPassword('password=****').length).toBe(0);
    expect(ruleLogPlaintextPassword('password=[REDACTED]').length).toBe(0);
    expect(ruleLogPlaintextPassword('password=null').length).toBe(0);
  });
});

describe('Bearer / JWT rule (LOG-SEC-002)', () => {
  test('fires on Authorization: Bearer ...', () => {
    expect(ruleLogBearerOrJwt('Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123').length).toBe(1);
  });

  test('fires on JWT-shaped token', () => {
    expect(ruleLogBearerOrJwt('token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxw').length).toBe(1);
  });
});

describe('Service API key rule (LOG-SEC-003)', () => {
  test('fires on Stripe live key', () => {
    expect(ruleLogServiceApiKey('using key sk_live_4eC39HqLyjWDarjtT1zdp7dc to charge').length).toBe(1);
  });

  test('fires on AWS access key', () => {
    expect(ruleLogServiceApiKey('AKIAIOSFODNN7EXAMPLE failed').length).toBe(1);
  });
});

describe('Private key rule (LOG-SEC-004)', () => {
  test('fires on PEM private key marker', () => {
    expect(ruleLogPrivateKey('-----BEGIN RSA PRIVATE KEY-----').length).toBe(1);
    expect(ruleLogPrivateKey('-----BEGIN PRIVATE KEY-----').length).toBe(1);
  });
});

describe('DB connection error rule (LOG-OPS-001)', () => {
  test('fires on connection-string-with-credentials', () => {
    expect(ruleLogDbConnError('mongo connect failed: mongodb://admin:Pa55@db:27017/app').length).toBe(1);
    expect(ruleLogDbConnError('postgresql://user:s3cret@db:5432/main').length).toBe(1);
  });

  test('does NOT fire on credential-less URIs', () => {
    expect(ruleLogDbConnError('postgresql://db:5432/main').length).toBe(0);
  });
});

describe('Redacted excerpt', () => {
  test('masks the matched substring while preserving context (PCI first-6-last-4 for PAN-shaped digits)', () => {
    const line = 'customer payment failed for card 4242424242424242 amount 100';
    const idx = line.indexOf('4242424242424242');
    const excerpt = buildRedactedExcerpt(line, idx, idx + 16);
    // PCI-DSS Req 3.3 — first 6 + last 4 may be retained. Middle 6 chars are masked.
    expect(excerpt).not.toContain('4242424242424242');
    expect(excerpt).toContain('424242'); // BIN
    expect(excerpt).toContain('4242'); // last 4
    expect(excerpt.match(/\*+/)?.[0].length).toBe(6);
  });
  test('non-PAN matches keep the older first-2-last-2 mask', () => {
    const line = 'user=alice@bank.ae signed in';
    const idx = line.indexOf('alice@bank.ae');
    const excerpt = buildRedactedExcerpt(line, idx, idx + 13);
    expect(excerpt).not.toContain('alice@bank.ae');
    expect(excerpt).toMatch(/al\*+ae/);
  });
});

describe('scanLogLine integration', () => {
  test('aggregates findings from all rules', () => {
    const line = 'login user=alice@bank.ae password=S3cretPass token=Bearer abcdef1234567890ABCDEFG';
    const matches = scanLogLine(line);
    const ruleIds = matches.map((m) => m.ruleId);
    expect(ruleIds).toContain('LOG-PII-003');
    expect(ruleIds).toContain('LOG-SEC-001');
    expect(ruleIds).toContain('LOG-SEC-002');
  });

  test('a clean operational log line produces zero matches', () => {
    expect(scanLogLine('GET /health 200 12ms').length).toBe(0);
    expect(scanLogLine('order processed orderId=ord_12345 amount=99.99 USD').length).toBe(0);
  });
});
