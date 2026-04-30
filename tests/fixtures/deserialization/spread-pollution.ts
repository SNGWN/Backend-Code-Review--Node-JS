import express from 'express';

const app = express();

// VULNERABLE: Spread with untrusted data
app.post('/api/create', (req, res) => {
  const userInput = JSON.parse(req.body);
  const newUser = {
    id: generateId(),
    ...userInput,
  };
  res.json(newUser);
});

// VULNERABLE: Spread merging configs
app.post('/api/config', (req, res) => {
  const defaultConfig = { debug: false, logging: true };
  const userConfig = JSON.parse(req.body);
  const config = { ...defaultConfig, ...userConfig };
  applyConfig(config);
  res.json({ status: 'updated' });
});

// VULNERABLE: Spread with query parameters
app.get('/api/search', (req, res) => {
  const baseQuery = { limit: 10, offset: 0 };
  const userQuery = { ...baseQuery, ...req.query };
  const results = search(userQuery);
  res.json(results);
});

// VULNERABLE: Nested spread operator
app.post('/api/nested', (req, res) => {
  const data = JSON.parse(req.body);
  const result = {
    user: {
      ...defaultUser,
      ...data,
    },
  };
  res.json(result);
});

// SAFE: Filter properties before spread
app.post('/api/safe', (req, res) => {
  const allowedProps = new Set(['name', 'email', 'age']);
  const userInput = JSON.parse(req.body);
  const safeInput = Object.fromEntries(
    Object.entries(userInput).filter(([key]) => allowedProps.has(key))
  );
  const newUser = {
    id: generateId(),
    ...safeInput,
  };
  res.json(newUser);
});

function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

function applyConfig(config: any) {
  // Apply config
}

function search(query: any) {
  // Search implementation
  return [];
}

const defaultUser = { role: 'user', isAdmin: false };
