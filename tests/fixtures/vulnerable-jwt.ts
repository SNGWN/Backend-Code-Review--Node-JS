import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

// VULNERABILITY 1: Using jwt.decode without jwt.verify
const WEAK_SECRET = 'short'; // Only 5 characters
const tokenCache: Record<string, any> = {};

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const token = jwt.sign({ userId: 123, username, isAdmin: false }, WEAK_SECRET, {
    expiresIn: '1h',
  });
  res.json({ token });
});

// VULNERABILITY 2: jwt.decode without verification
app.get('/api/user/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token' });
    return;
  }
  
  // CRITICAL: Using jwt.decode without jwt.verify
  const decoded = jwt.decode(token);
  res.json({ user: decoded });
});

// VULNERABILITY 3: Algorithm confusion - allowing 'none' algorithm
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, WEAK_SECRET, {
      algorithms: ['none', 'HS256'], // VULNERABLE: 'none' algorithm allowed
    });
    res.json({ valid: true, decoded });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABILITY 4: No algorithm specification
app.get('/api/secure-endpoint', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token' });
    return;
  }
  
  try {
    // VULNERABLE: No algorithm specification
    const decoded = jwt.verify(token, WEAK_SECRET);
    res.json({ data: 'secret data', user: decoded });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABILITY 5: Key confusion - using public key with HS256
const fs = require('fs');
const publicKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...'; // RSA public key

app.post('/api/auth/verify-rsa', (req, res) => {
  const { token } = req.body;
  try {
    // VULNERABLE: Using public key (for RS256) with HS256
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['HS256'],
    });
    res.json({ valid: true, decoded });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABILITY 6: Missing expiration validation
app.get('/api/admin/dashboard', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token' });
    return;
  }
  
  try {
    // VULNERABLE: Ignoring expiration
    const decoded = jwt.verify(token, WEAK_SECRET, {
      ignoreExpiration: true, // CRITICAL: Expired tokens accepted
    });
    
    if (decoded.isAdmin) {
      res.json({ adminPanel: true, data: 'sensitive' });
    } else {
      res.status(403).json({ error: 'Not admin' });
    }
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABILITY 7: Cached token without expiration validation
app.get('/api/user/cached', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token' });
    return;
  }
  
  // VULNERABLE: Token cached indefinitely without validation
  if (tokenCache[token]) {
    const decoded = tokenCache[token];
    res.json({ user: decoded });
    return;
  }
  
  try {
    const decoded = jwt.decode(token); // Not even verified!
    tokenCache[token] = decoded;
    res.json({ user: decoded });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// VULNERABILITY 8: Missing kid (key ID) validation
app.get('/api/keyid-check', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token' });
    return;
  }
  
  try {
    const decoded = jwt.decode(token, { complete: true }) as any;
    const keyId = decoded.header.kid;
    
    // VULNERABLE: Using kid without validating it
    const keys: Record<string, string> = {
      'valid-key-1': WEAK_SECRET,
      'valid-key-2': 'another-weak-secret',
    };
    
    const key = keys[keyId]; // Kid not validated - attacker can specify any kid
    if (!key) {
      res.status(401).json({ error: 'Unknown key' });
      return;
    }
    
    const verified = jwt.verify(token, key);
    res.json({ valid: true, decoded: verified });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

export default app;
