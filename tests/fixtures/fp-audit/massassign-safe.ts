// MASS_ASSIGNMENT FP exhibits. Zero default findings expected.
import express from 'express';
const app = express();

// (1) Object.assign with a constant source.
const merged = Object.assign({}, { a: 1, b: 2 });

// (2) Object.assign with a whitelist-extracted source.
const allow = (b: Record<string, unknown>) => ({ name: b.name, email: b.email });
app.put('/api/profile', (req, res) => {
  const safe = allow(req.body);
  const user = Object.assign({}, safe);
  res.json(user);
});

// (3) Spread of an explicitly-validated source.
import { z } from 'zod';
const profileSchema = z.object({ name: z.string(), email: z.string() });
app.put('/api/profile2', (req, res) => {
  const safe = profileSchema.parse(req.body);
  const merged2 = { ...safe, updatedAt: Date.now() };
  res.json(merged2);
});

// (4) Property assignments to user.* from constants, not req.*.
app.post('/api/seed', (_req, res) => {
  const user: { name?: string; email?: string } = {};
  user.name = 'seed';
  user.email = 'seed@example.com';
  res.json(user);
});

// (5) Object literal containing fields named `role` but not from user input.
const rolesByPlan = { free: 'user', pro: 'editor', enterprise: 'admin' };
void merged; void rolesByPlan;

export default app;
