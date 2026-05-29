// SSRF + Open Redirect + Path Traversal + Tagged-SQL + Weak-randomness fixtures.
import express from 'express';
import * as fs from 'fs';
import * as path from 'path';

const app = express();
declare const fetch: (url: string, init?: unknown) => Promise<unknown>;
declare const axios: { get: (url: string) => Promise<unknown> };

// (1) SSRF — fetch with user-controlled URL.
app.get('/api/fetch', async (req, res) => {
  const target = String(req.query.url);
  const data = await fetch(target);
  res.json({ data });
});

// (2) SSRF — axios with templated user input.
app.post('/api/proxy', async (req, res) => {
  const upstream = await axios.get(`https://internal.svc/${req.body.path}`);
  res.json({ upstream });
});

// (3) Open redirect.
app.get('/api/go', (req, res) => {
  const dest = String(req.query.to);
  res.redirect(dest);
});

// (4) Path traversal — readFile.
app.get('/api/files', (req, res) => {
  const filename = String(req.query.name);
  const buf = fs.readFileSync(path.join('/var/data', filename));
  res.send(buf);
});

// (5) Tagged-template SQL injection.
const sql = (..._args: unknown[]) => ({});
app.get('/api/lookup', async (req, res) => {
  const id = String(req.query.id);
  const row = sql`SELECT * FROM users WHERE id=${id}`;
  res.json(row);
});

// (6) Weak randomness for session id.
function newSession(): { sessionId: string } {
  const sessionId = Math.random().toString(36).slice(2);
  return { sessionId };
}

// (7) Reset code.
function makeResetCode(): string {
  const resetCode = Math.floor(Math.random() * 1_000_000).toString();
  return resetCode;
}

void newSession; void makeResetCode; export default app;
