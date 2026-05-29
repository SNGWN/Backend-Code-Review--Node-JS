// Aliased dangerous-API imports — every block here should be flagged.
import { exec as runShell } from 'child_process';
import { readFileSync as slurp } from 'fs';
import express from 'express';

const app = express();

// (1) Renamed exec — bare `exec` regex wouldn't catch this.
app.post('/api/run', (req, res) => {
  runShell(req.body.cmd, (_err, stdout) => res.send(stdout));
});

// (2) Renamed readFileSync.
app.get('/api/file', (req, res) => {
  const name = String(req.query.name);
  const buf = slurp(name);
  res.send(buf);
});

export default app;
