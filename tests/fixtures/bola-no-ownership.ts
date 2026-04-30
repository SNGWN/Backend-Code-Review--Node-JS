// VULNERABLE: No ownership verification
import express from 'express';

const app = express();

// ❌ VULNERABLE: Database query without ownership check
app.post('/api/users/:id/delete', (req, res) => {
  const userId = req.params.id;
  
  // VULNERABLE: Deleting user by ID without checking if requester owns it
  const result = db.User.deleteWhere({ id: userId });
  
  // Attacker can delete any user by changing the ID parameter
  res.json({ deleted: true });
});

// ❌ VULNERABLE: Updating resource without ownership verification
app.patch('/api/profile/:userId', (req, res) => {
  const userId = req.params.userId;
  
  const user = db.User.findById(userId);
  
  // MISSING: Check if req.user.id === userId
  // No horizontal escalation protection
  user.email = req.body.email;
  user.phone = req.body.phone;
  user.twoFactorEnabled = false;
  user.save();
  
  res.json(user);
});

// ❌ VULNERABLE: Accessing sensitive data without owner verification
app.get('/api/users/:userId/settings', (req, res) => {
  const userId = req.params.userId;
  
  // This query doesn't filter by owner
  const settings = db.Setting.where({ userId: userId }).first();
  
  // VULNERABLE: Any authenticated user can access any user's settings
  res.json(settings);
});
