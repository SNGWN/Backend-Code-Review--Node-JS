// MIXED: Multiple types of issues
import express from 'express';

const app = express();

// ❌ VULNERABLE: Missing BOTH authentication AND authorization
app.delete('/api/data/:dataId', (req, res) => {
  const dataId = req.params.dataId;
  db.Data.deleteById(dataId);
  res.json({ success: true });
});

// ❌ VULNERABLE: Has auth but missing authz check
app.get('/api/users/:userId/profile', authMiddleware, (req, res) => {
  const userId = req.params.userId;
  const user = db.User.findById(userId);
  // No ownership verification
  res.json(user);
});

// ✓ SECURE: Proper auth and authz
app.get('/api/users/:userId/orders', authMiddleware, (req, res) => {
  const userId = req.params.userId;
  
  if (userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const orders = db.Order.where({ userId }).all();
  res.json(orders);
});

// ❌ VULNERABLE: Admin endpoint without role check
function resetPassword(userId, newPassword) {
  // No check if caller is admin
  const user = db.User.findById(userId);
  user.password = hashPassword(newPassword);
  user.save();
  return user;
}
