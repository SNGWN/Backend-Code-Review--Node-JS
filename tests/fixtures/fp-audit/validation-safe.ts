// VALIDATION-rule FP exhibits. Zero default findings expected.
import express from 'express';
import { z } from 'zod';
const app = express();

// (1) Substring sink names that ARE NOT the real sink.
function executeMigration(name: string): void { console.log('migration', name); }
function userQuery(input: string): string { return input.toLowerCase(); }
function rawValue(input: string): string { return input.trim(); }
function queryString(o: Record<string, string>): string { return Object.entries(o).map(([k, v]) => `${k}=${v}`).join('&'); }
function executeJob(name: string): void { console.log('job', name); }
function executeWorkflow(id: number): void { console.log('workflow', id); }

// (2) JSON.parse with non-tainted input.
const safeJson: unknown = JSON.parse('{"a":1}');
const fromEnv: unknown = JSON.parse(process.env.CONFIG ?? '{}');
function parseFromFile(path: string) { return JSON.parse(require('fs').readFileSync(path, 'utf-8')); }
void safeJson; void fromEnv; void parseFromFile;

// (3) JSON.parse with tainted input that was VALIDATED first via zod.
app.post('/api/safe-parse', (req, res) => {
  const schema = z.object({ id: z.number() });
  const validated = schema.parse(req.body);
  const json = JSON.stringify(validated);
  const parsed: unknown = JSON.parse(json);
  res.json(parsed);
});

// (4) setTimeout with function arg — the SAFE form, never code injection.
setTimeout(() => console.log('done'), 100);
setTimeout(function () { console.log('done'); }, 100);

// (5) Aliased import shadowing — `parse` from a different module is NOT JSON.parse.
import { parse as parseUrl } from 'url';
app.get('/redirect', (req, res) => {
  const target = parseUrl(String(req.query.url));
  res.json({ host: target.host });
});

// (6) fs reads with constant file paths.
import { readFileSync, writeFileSync } from 'fs';
readFileSync('/etc/config.json');
writeFileSync('/tmp/output.txt', 'hello');

// (7) sql-like words inside strings that are NOT queries.
const text = 'How to update your profile';
const helpDoc = 'SELECT a region';
const where = 'where to find help';
void text; void helpDoc; void where;

// (8) Object spread of validated input.
app.post('/api/preferences', (req, res) => {
  const schema = z.object({ theme: z.string() });
  const safe = schema.parse(req.body);
  const merged = { ...safe, updatedAt: Date.now() };
  res.json(merged);
});

export default app;
