// Misconfiguration + new-detector fixtures. Each block fires a specific rule.
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

const app = express();

// (1) BCR-MISC-001: CORS wildcard
app.use(cors({ origin: '*' }));
app.use(cors()); // also permissive

// (2) BCR-MISC-002: body parser without limit
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// (3) BCR-MISC-003: helmet no opts
app.use(helmet());

// (4) BCR-MISC-004: bcrypt cost too low
async function hashWeak(pw: string) {
  return bcrypt.hash(pw, 8);
}
async function genSaltWeak() {
  return bcrypt.genSalt(8);
}

// (5) BCR-CRYPTO-005: deprecated createCipher
function encryptDeprecated(plaintext: string, key: string): string {
  const cipher = crypto.createCipher('aes-256-cbc', key);
  return cipher.update(plaintext, 'utf-8', 'hex') + cipher.final('hex');
}

// (6) BCR-MA-006: service(req.body) without validation
const userService = {
  createUser: (data: unknown) => data,
  updateUser: (id: string, data: unknown) => ({ id, data }),
};
app.post('/api/users', async (req, res) => {
  const user = await userService.createUser(req.body);
  res.json(user);
});

// (7) BCR-VAL-012: base64 deserialization
app.post('/api/basic-auth', (req, res) => {
  const header = String(req.headers.authorization ?? '');
  const decoded = Buffer.from(header.slice(6), 'base64').toString();
  const [username, password] = decoded.split(':');
  res.json({ username, password });
});

export default app;
