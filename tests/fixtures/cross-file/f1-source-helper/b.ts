import express from 'express';
import { getId } from './a';

const app = express();
const db = { query: (_sql: string): unknown[] => [] };

// Tainted return from getId() flows into a raw SQL string. Single-file scanning
// misses this because the source (req.params.id) lives in a.ts.
app.get('/users/:id', (req, res) => {
  const rows = db.query(`SELECT * FROM users WHERE id=${getId(req)}`);
  res.json(rows);
});

export default app;
