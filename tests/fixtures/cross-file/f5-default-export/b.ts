import express from 'express';
import getId from './a';

const app = express();
const db = { query: (_sql: string): unknown[] => [] };

app.get('/users/:id', (req, res) => {
  const rows = db.query(`SELECT * FROM users WHERE id=${getId(req)}`);
  res.json(rows);
});

export default app;
