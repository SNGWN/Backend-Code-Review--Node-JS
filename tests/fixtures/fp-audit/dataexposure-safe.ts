// DATA_EXPOSURE FP exhibits. Zero default findings expected.
import express from 'express';
const app = express();

// (1) Responses whose BODY contains the WORD password/token/secret in a label.
// NOTE: /password/reset and /tokens/* endpoints LEGITIMATELY warrant auth/rate-limit
// review, so we exercise the "label contains sensitive word" pattern on a non-sensitive
// route here.
app.get('/api/messages/preview', (_req, res) => {
  res.json({ status: 'sent', message: 'password reset link emailed' });
});
app.get('/api/docs/glossary', (_req, res) => {
  res.json({ tokenName: 'access_token', description: 'short-lived auth token' });
});

// (2) Responses that exclude sensitive fields via destructuring or pick.
app.get('/api/users/:id', (_req, res) => {
  const user = { id: 1, name: 'a', email: 'a@b.com', password: 'x', token: 'y' };
  const { password, token, ...safe } = user;
  void password; void token;
  res.json(safe);
});

// (3) Returns with constant payloads (not user objects).
app.get('/api/config', (_req, res) => res.json({ feature: 'x', enabled: true }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// (4) Response that mentions credit-card NUMBER label, but the data is masked.
app.get('/api/cards/:id', (_req, res) => {
  res.json({ id: 'card_1', last4: '4242', brand: 'visa' });
});

// (5) Helpful error messages without leaking sensitive data.
app.use((_err: unknown, _req: express.Request, res: express.Response, _next: unknown) => {
  res.status(500).json({ error: 'internal_error' });
});

export default app;
