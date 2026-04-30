import express from 'express';

const app = express();

// VULNERABLE: Object.assign with untrusted source
app.post('/api/merge', (req, res) => {
  const userObj = JSON.parse(req.body);
  const appObj = { userId: 123, role: 'user' };
  Object.assign(appObj, userObj);
  res.json(appObj);
});

// VULNERABLE: Object.assign without validation
app.put('/api/user/:id', (req, res) => {
  const user = getUser(req.params.id);
  Object.assign(user, req.body);
  db.save(user);
  res.json(user);
});

// VULNERABLE: Merging configs with Object.assign
app.post('/api/config', (req, res) => {
  const baseConfig = { debug: false, timeout: 5000 };
  const userConfig = JSON.parse(req.body);
  const finalConfig = Object.assign(baseConfig, userConfig);
  applyConfig(finalConfig);
  res.json({ status: 'ok' });
});

// SAFE: Use whitelist with Object.assign
app.post('/api/safe', (req, res) => {
  const userInput = JSON.parse(req.body);
  const allowedKeys = new Set(['name', 'email', 'phone']);
  const safeObj = {};
  for (const [key, value] of Object.entries(userInput)) {
    if (allowedKeys.has(key)) {
      Object.assign(safeObj, { [key]: value });
    }
  }
  res.json(safeObj);
});
