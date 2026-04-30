// VULNERABLE: Missing authorization check
import express from 'express';

const app = express();

// ❌ VULNERABLE: No authorization check on admin endpoint
app.delete('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const result = db.User.deleteById(userId);
  res.json({ success: true });
});

// ❌ VULNERABLE: Sensitive operation without authz
app.put('/api/settings/admin', (req, res) => {
  const settings = req.body;
  config.update(settings);
  res.json({ updated: true });
});

// ❌ VULNERABLE: Profile update without ownership check
app.patch('/api/users/:id/profile', (req, res) => {
  const user = db.User.findById(req.params.id);
  user.email = req.body.email;
  user.save();
  res.json(user);
});
