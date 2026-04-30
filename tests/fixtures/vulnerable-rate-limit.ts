import express from 'express';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());

// VULNERABILITY 1: Missing rate limiting on login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // No rate limiting middleware - allows brute force
  res.json({ success: true, token: 'jwt-token' });
});

// VULNERABILITY 2: Missing rate limiting on registration
app.post('/register', (req, res) => {
  // No rate limiting - allows account enumeration and DoS
  const user = req.body;
  res.json({ created: true, userId: 123 });
});

// VULNERABILITY 3: Missing rate limiting on password reset
app.post('/forgot-password', (req, res) => {
  // No protection - allows email enumeration and spam
  res.json({ success: true, message: 'Reset email sent' });
});

// VULNERABILITY 4: Rate limiting with header bypass vulnerability
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute - too high for login
  keyGenerator: (req) => {
    // Vulnerable: uses req.ip directly without validating trusted proxies
    return req.ip;
  },
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { email, password } = req.body;
  // User can spoof X-Forwarded-For header to bypass rate limit
  res.json({ token: 'jwt' });
});

// VULNERABILITY 5: Global-only rate limiting without per-user limits
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000, // Global limit
  // No keyGenerator for per-user tracking
});

app.get('/api/export', globalLimiter, (req, res) => {
  // Users can distribute requests across accounts to bypass
  res.json({ data: 'large dataset' });
});

// VULNERABILITY 6: Weak rate limits on sensitive endpoint
const weakLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200, // 200 req/min is too high for /api/admin
});

app.get('/api/admin/users', weakLimiter, (req, res) => {
  // Weak limit allows brute force
  res.json({ users: [] });
});

// VULNERABILITY 7: In-memory rate limiting without distributed cache
const memoryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  // Uses default MemoryStore - not shared across load-balanced servers
  // In production with multiple servers, each instance has separate counters
  skip: (req) => {
    // Missing account lockout logic
    return false;
  },
});

app.post('/api/admin/login', memoryLimiter, (req, res) => {
  // Distributed bypass possible via load balancer
  res.json({ token: 'admin-token' });
});

// VULNERABILITY 8: Missing reset mechanism
let failedAttempts = 0;

app.post('/api/keys', (req, res) => {
  // No rate limiting, no reset mechanism
  // No account lockout protection
  res.json({ apiKey: 'sk-1234567890' });
});

// VULNERABILITY 9: No account lockout protection
app.post('/api/secrets', (req, res) => {
  const { secretName } = req.body;
  // No rate limiting or account lockout
  // Allows unlimited attempts to guess secret names
  res.json({ secret: 'value' });
});

// VULNERABILITY 10: Missing protection on sensitive operation
app.get('/api/export/all', (req, res) => {
  // No rate limiting on data export
  // Allows rapid data exfiltration
  res.json({ data: 'all sensitive data' });
});

export default app;
