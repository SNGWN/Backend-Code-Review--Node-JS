// AUTH-rule FP exhibits. Every block here must produce ZERO findings under default settings.
import express from 'express';
const app = express();

// (1) Sensitive-named vars holding obviously-non-secret values.
export const SECRET_HEADER_NAME = 'X-Secret-Header';
export const TOKEN_KEY = 'authToken';
export const PASSWORD_FIELD = 'password';
export const API_KEY_HEADER = 'X-Api-Key';

// (2) Placeholder/dev sentinels.
export const DEFAULT_SECRET = 'changeme';
export const DEV_TOKEN = 'your-token-here';
export const PLACEHOLDER_KEY = 'example';
export const TEST_SECRET = 'todo';

// (3) Path-like and enum-like literals in credential-named slots.
export const SECRET_PATH = '/etc/secrets/main.json';
export const KEY_ENUM = 'KEY_ALPHA';

// (4) Public routes by design — no auth needed.
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/metrics', (_req, res) => res.json({ ok: true }));
app.get('/version', (_req, res) => res.json({ version: '1.0.0' }));

// (5) Routes with explicit auth middleware (should not flag "sensitive without guard").
function requireAuth(_req: unknown, _res: unknown, next: () => void) { next(); }
function requireAdmin(_req: unknown, _res: unknown, next: () => void) { next(); }
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (_req, res) => res.json({ deleted: true }));
app.post('/api/admin/role', requireAuth, requireAdmin, (_req, res) => res.json({ assigned: true }));

// (6) Token *read* with downstream verify in scope.
function readTokenSafely(req: { token: string }): string | null {
  const token = req.token;
  const verified = verifyToken(token);
  if (!verified) return null;
  return verified;
}
function verifyToken(t: string): string | null { return t; }

export { readTokenSafely };
