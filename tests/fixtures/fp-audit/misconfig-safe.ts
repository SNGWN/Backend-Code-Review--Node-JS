// Misconfiguration-safe patterns. Zero default findings expected.
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { z } from 'zod';

const app = express();

// (1) CORS with explicit allowlist.
app.use(cors({ origin: ['https://app.example.com', 'https://api.example.com'] }));
app.use(cors({ origin: (origin, cb) => cb(null, origin === 'https://app.example.com') }));

// (2) Body parser with explicit limit.
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// (3) Helmet with explicit options.
app.use(helmet({ contentSecurityPolicy: { directives: { 'default-src': ["'self'"] } } }));

// (4) bcrypt with safe cost.
async function hashSafe(pw: string) {
  return bcrypt.hash(pw, 12);
}
async function genSaltSafe() {
  return bcrypt.genSalt(12);
}

// (5) Modern createCipheriv.
function encryptSafe(plaintext: string, key: Buffer): { ciphertext: string; iv: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = cipher.update(plaintext, 'utf-8', 'hex') + cipher.final('hex');
  return { ciphertext, iv: iv.toString('hex') };
}

// (6) Mass-assign with validation in scope.
function requireAuth(_req: unknown, _res: unknown, next: () => void) { next(); }
function requireAdmin(_req: unknown, _res: unknown, next: () => void) { next(); }
const userService = {
  createUser: (data: unknown) => data,
};
const userSchema = z.object({ name: z.string(), email: z.string() });
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const validated = userSchema.parse(req.body);
  const user = await userService.createUser(validated);
  res.json(user);
});

// (7) Mass-assign with explicit field pick — still safe.
app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { name, email } = req.body;
  const user = await userService.createUser({ name, email });
  res.json(user);
});

// (8) Base64 decode of a CONSTANT (not user input).
const SIGNED_SECRET = Buffer.from('Y29uc3RhbnQ=', 'base64').toString();

void encryptSafe; void hashSafe; void genSaltSafe; void SIGNED_SECRET;
export default app;
