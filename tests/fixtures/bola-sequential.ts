// VULNERABLE: BOLA with sequential IDs
import express from 'express';

const app = express();

// ❌ VULNERABLE: Accessing userId directly without ownership check
app.get('/api/users/:userId/profile', (req, res) => {
  const userId = req.params.userId;
  const user = db.User.findById(userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // MISSING: Check if authenticated user owns this profile
  // Attacker can enumerate IDs: /api/users/1, /api/users/2, etc.
  res.json(user);
});

// ❌ VULNERABLE: Order access without ownership verification
app.get('/api/orders/:orderId', (req, res) => {
  const orderId = req.params.orderId;
  const order = db.Order.findById(orderId);
  
  // VULNERABLE: No check that req.user.id == order.userId
  // Attacker can access any order by guessing IDs
  res.json(order);
});

// ❌ VULNERABLE: Invoice enumeration by predictable ID
app.get('/api/invoices/:invoiceId', (req, res) => {
  const invoiceId = req.params.invoiceId;
  const invoice = db.Invoice.findById(invoiceId);
  
  // VULNERABLE: Sequential IDs allow enumeration
  // /api/invoices/1001, /api/invoices/1002, etc.
  res.json(invoice);
});
