import express from 'express';
import { runShell } from './a';

const app = express();

// `runShell` is `exec` from child_process via the barrel; cross-file resolution
// trips the command-execution rule on the renamed local name.
app.post('/run', (req, res) => {
  runShell(req.body.cmd, (_err: unknown, stdout: unknown) => res.send(stdout));
});

export default app;
