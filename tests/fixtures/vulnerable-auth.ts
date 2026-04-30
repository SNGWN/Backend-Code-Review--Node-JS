import express from 'express';

const app = express();
app.use(express.json());

const SECRET_KEY = 'hardcoded-secret-key-12345';
const API_PASSWORD = 'admin123';

// VULNERABILITY 1: Missing authentication middleware on route
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  res.json({ id: userId, data: 'sensitive data' });
});

// VULNERABILITY 2: Direct Object.assign with req.body
app.post('/api/users', (req, res) => {
  const user = {};
  Object.assign(user, req.body);
  res.json(user);
});

// VULNERABILITY 3: Unvalidated request body usage
app.post('/api/products', (req, res) => {
  const productData = req.body;
  console.log('Creating product:', productData);
  res.json({ created: true, data: productData });
});

// VULNERABILITY 4: Sensitive data logging
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`User login attempt: ${username} with password: ${password}`);
  console.log('API Key:', 'sk-1234567890abcdefg');
  res.json({ success: true });
});

// VULNERABILITY 5: Unverified token usage
app.get('/api/admin', (req, res) => {
  const token = req.headers.authorization;
  const decoded = { userId: 123 };
  res.json({ admin: decoded });
});

// VULNERABILITY 6: Missing validation on delete operation
app.delete('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  console.log('Deleting user:', userId);
  res.json({ deleted: true });
});

// VULNERABILITY 7: Direct property assignment from request
app.put('/api/profile', (req, res) => {
  const profile = {};
  profile.name = req.body.name;
  profile.email = req.body.email;
  profile.role = req.body.role;
  profile.isAdmin = req.body.isAdmin;
  res.json(profile);
});

export default app;
