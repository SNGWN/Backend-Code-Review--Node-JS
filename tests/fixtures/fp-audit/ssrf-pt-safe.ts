// SSRF/PT/tagged-SQL FP exhibits. Zero default findings expected.
import express from 'express';
import * as fs from 'fs';
import * as path from 'path';

const app = express();
declare const fetch: (url: string, init?: unknown) => Promise<unknown>;
declare const axios: { get: (url: string) => Promise<unknown> };

// (1) Outbound fetch with constant URL.
async function pollHealth(): Promise<unknown> {
  return fetch('https://api.internal.example.com/health');
}

// (2) Outbound axios where URL is built from validated input via zod.
import { z } from 'zod';
app.get('/api/proxy', async (req, res) => {
  const schema = z.object({ host: z.enum(['allowed-1.example.com', 'allowed-2.example.com']) });
  const { host } = schema.parse(req.query);
  const upstream = await axios.get(`https://${host}/v1/status`);
  res.json(upstream);
});

// (3) Relative-path redirect — safe.
app.get('/api/go-home', (_req, res) => res.redirect('/home'));
app.get('/api/relative-redirect', (req, res) => res.redirect(`/users/${(req as { user: { id: string } }).user.id}`));

// (4) Path-traversal-safe: path resolved inside a base directory with containment check.
const BASE_DIR = '/var/data';
app.get('/api/files', (req, res) => {
  const name = String(req.query.name);
  const resolved = path.resolve(BASE_DIR, name);
  if (!resolved.startsWith(BASE_DIR)) return res.status(400).end();
  const buf = fs.readFileSync(resolved);
  res.send(buf);
});

// (5) sql template with constant or numeric-only substitutions.
const sql = (..._args: unknown[]) => ({});
function lookupById(): unknown {
  const id = 42;
  return sql`SELECT * FROM users WHERE id=${id}`;
}

// (6) Non-sensitive Math.random uses.
function jitterMs(): number { return Math.floor(Math.random() * 100); }
function pickShard(): number { return Math.floor(Math.random() * 4); }

// (7) Open-redirect-safe via allowlist.
const ALLOWED_REDIRECTS = new Set(['/home', '/dashboard', '/profile']);
app.get('/api/go', (req, res) => {
  const to = String(req.query.to);
  if (!ALLOWED_REDIRECTS.has(to)) return res.status(400).end();
  res.redirect(to);
});

void pollHealth; void lookupById; void jitterMs; void pickShard;
export default app;
