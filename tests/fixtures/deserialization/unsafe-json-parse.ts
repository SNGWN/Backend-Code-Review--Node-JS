import express from 'express';

const app = express();

// VULNERABLE: Unsafe JSON.parse with user input
app.post('/api/user', (req, res) => {
  const userData = JSON.parse(req.body);
  if (userData.isAdmin) {
    res.json({ message: 'Admin access granted' });
  } else {
    res.json({ message: 'Regular user' });
  }
});

// VULNERABLE: JSON.parse without reviver
app.post('/api/data', (req, res) => {
  const data = JSON.parse(req.query.data as string);
  const newObj = {};
  Object.assign(newObj, data);
  res.json(newObj);
});

// SAFE: JSON.parse with reviver function
app.post('/api/safe', (req, res) => {
  const data = JSON.parse(req.body, (key, value) => {
    if (key === '__proto__' || key === 'constructor') {
      return undefined;
    }
    return value;
  });
  res.json(data);
});

// VULNERABLE: No validation before deserialization
app.post('/api/config', (req, res) => {
  const config = JSON.parse(req.body);
  // Directly use config without validation
  process.env.APP_CONFIG = JSON.stringify(config);
  res.json({ status: 'updated' });
});
