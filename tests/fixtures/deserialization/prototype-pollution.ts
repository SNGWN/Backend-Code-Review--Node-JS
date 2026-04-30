// VULNERABLE: Direct __proto__ assignment
export function pollutedAssignment(userInput: any) {
  const obj = {};
  obj['__proto__'] = userInput;
  return obj;
}

// VULNERABLE: Constructor.prototype pollution
export function constructorPollution(userInput: any) {
  const obj = {};
  obj['constructor']['prototype'] = userInput;
  return obj;
}

// VULNERABLE: Dynamic property with dangerous name
export function dynamicPollution(prop: string, value: any) {
  const obj = {};
  obj[prop] = value; // If prop is '__proto__', prototype pollution occurs
  return obj;
}

import express from 'express';

const app = express();

// VULNERABLE: Prototype pollution in route handler
app.post('/api/set-property', (req, res) => {
  const key = req.body.key;
  const value = req.body.value;
  const obj = {};
  obj[key] = value; // __proto__ can be set here
  res.json({ status: 'set' });
});

// VULNERABLE: Constructor assignment
app.post('/api/clone', (req, res) => {
  const template = {};
  for (const [key, val] of Object.entries(req.body)) {
    template[key] = val; // Can pollute via __proto__
  }
  res.json(template);
});

// SAFE: Filter dangerous properties
app.post('/api/safe-set', (req, res) => {
  const key = req.body.key;
  const value = req.body.value;
  
  // Reject dangerous property names
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    return res.status(400).json({ error: 'Invalid property' });
  }
  
  const obj = {};
  obj[key] = value;
  res.json({ status: 'set' });
});

// SAFE: Use Object.create(null)
app.post('/api/safe-clone', (req, res) => {
  const template = Object.create(null);
  const allowedKeys = new Set(['name', 'email', 'age']);
  
  for (const [key, val] of Object.entries(req.body)) {
    if (allowedKeys.has(key)) {
      template[key] = val;
    }
  }
  
  res.json(template);
});
