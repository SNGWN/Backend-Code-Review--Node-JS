// CRYPTO_WEAKNESS FP exhibits. Zero default findings expected.
import crypto from 'crypto';

// (1) MD5/SHA1 used for NON-secret purposes (cache keys, file integrity).
function cacheKey(input: string): string {
  return crypto.createHash('md5').update(input).digest('hex');
}
function fileChecksum(buf: Buffer): string {
  return crypto.createHash('sha1').update(buf).digest('hex');
}

// (2) Math.random for non-token purposes (jitter, UI animation delay).
function jitterMs(): number {
  return Math.floor(Math.random() * 100);
}
function pickRandomSlot(): number {
  return Math.floor(Math.random() * 10);
}

// (3) Mentions of secret/key with structured assignments to env, not literals.
const dbConfig = {
  host: 'db.example.com',
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
};

// (4) Cryptographically safe random for actual security uses.
function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
function generateNonce(): string {
  return crypto.randomUUID();
}

void cacheKey; void fileChecksum; void jitterMs; void pickRandomSlot; void dbConfig; void generateSecureToken; void generateNonce;
