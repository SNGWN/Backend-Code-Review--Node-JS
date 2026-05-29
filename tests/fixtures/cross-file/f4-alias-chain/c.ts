import express from 'express';
import { cmd } from './b';

const app = express();

// `cmd` traces through b.ts → a.ts → child_process.exec; cross-file resolver
// follows the chain.
app.post('/run', (req, res) => {
  cmd(req.body.cmd, (_err: unknown, stdout: unknown) => res.send(stdout));
});

export default app;
