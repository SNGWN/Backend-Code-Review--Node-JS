// RATE_LIMITING FP exhibits. Zero default findings expected.
import express from 'express';
import rateLimit from 'express-rate-limit';
const app = express();

// (1) Sensitive endpoint with PROPER rate limit using distributed store.
const loginLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  store: new (class { /* fake redis store */ }) as never,
});
const adminLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  keyGenerator: (req: express.Request) => `${req.ip}:${(req as { user?: { id: string } }).user?.id}`,
});

function requireAuth(_req: unknown, _res: unknown, next: () => void) { next(); }
function requireAdmin(_req: unknown, _res: unknown, next: () => void) { next(); }

app.post('/login', loginLimiter, (_req, res) => res.json({ ok: true }));
app.post('/api/admin/role', requireAuth, requireAdmin, adminLimiter, (_req, res) => res.json({ ok: true }));

// (2) Public endpoint with no rate limit and no sensitive content.
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/api/products', (_req, res) => res.json([]));

// (3) Endpoint with rate limit + redis store (distributed).
app.post('/api/keys', rateLimit({ windowMs: 60_000, max: 5, store: { /* redis-like */ } as never }), (_req, res) => {
  res.json({ created: true });
});
