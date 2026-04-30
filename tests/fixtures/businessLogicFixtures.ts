/**
 * Test fixtures for Business Logic Detector
 */

export const raceConditionCode = `
async function transferFunds(fromId: string, toId: string, amount: number) {
  const balance = await db.query('SELECT balance FROM accounts WHERE id = ?', [fromId]);
  
  if (balance[0].balance >= amount) {
    await db.query('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, fromId]);
    await db.query('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amount, toId]);
  }
}
`;

export const missingIdempotencyCode = `
app.post('/api/charge', async (req, res) => {
  const { cardToken, amount } = req.body;
  
  const charge = await stripe.charges.create({
    amount: amount,
    currency: 'usd',
    source: cardToken
  });
  
  res.json({ success: true, chargeId: charge.id });
});
`;

export const insufficientFundsCode = `
async function withdraw(userId: string, amount: number) {
  const account = await db.query('SELECT balance FROM accounts WHERE id = ?', [userId]);
  
  if (account[0].balance >= amount) {
    // Debit without transaction
    await db.query('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, userId]);
    return { success: true };
  }
}
`;

export const clientSidePriceCode = `
app.post('/api/checkout', async (req, res) => {
  const { items, total } = req.body; // Price comes from client
  
  const charge = await stripe.charges.create({
    amount: total * 100,
    currency: 'usd',
    source: req.body.cardToken
  });
  
  res.json({ orderId: charge.id });
});
`;

export const inventoryOverSellingCode = `
app.post('/api/purchase', async (req, res) => {
  const { productId, quantity } = req.body;
  
  const product = await db.query(
    'SELECT quantity FROM inventory WHERE product_id = ?',
    [productId]
  );
  
  if (product[0].quantity >= quantity) {
    // Not atomic - race condition possible
    await db.query(
      'UPDATE inventory SET quantity = quantity - ? WHERE product_id = ?',
      [quantity, productId]
    );
  }
});
`;

export const workflowBypassCode = `
app.post('/api/checkout', async (req, res) => {
  const { orderId } = req.body;
  // No verification that payment was processed
  // No check that inventory was reserved
  
  await db.query('UPDATE orders SET status = "completed" WHERE id = ?', [orderId]);
  res.json({ success: true });
});
`;

export const stateMachineBypassCode = `
app.post('/api/order/:orderId/complete', async (req, res) => {
  const orderId = req.params.orderId;
  
  // No verification of current state
  // Can transition from any state to "completed"
  await db.query(
    'UPDATE orders SET status = "completed" WHERE id = ?',
    [orderId]
  );
  
  res.json({ success: true });
});
`;

export const missingBalanceVerificationCode = `
async function processRefund(userId: string, amount: number) {
  // No verification that user actually has sufficient balance/credits
  await db.query(
    'UPDATE user_credits SET balance = balance + ? WHERE user_id = ?',
    [amount, userId]
  );
}
`;

export const fixedRaceConditionCode = `
async function transferFunds(fromId: string, toId: string, amount: number) {
  const transaction = await db.transaction();
  try {
    const balance = await transaction.sequelize.query(
      'SELECT balance FROM accounts WHERE id = ? FOR UPDATE',
      { replacements: [fromId] }
    );
    
    if (balance[0][0].balance < amount) {
      throw new Error('Insufficient funds');
    }
    
    await transaction.query('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, fromId]);
    await transaction.query('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amount, toId]);
    await transaction.commit();
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
}
`;

export const fixedIdempotencyCode = `
app.post('/api/charge', async (req, res) => {
  const { cardToken, amount, idempotencyKey } = req.body;
  
  // Check if already processed
  const existing = await db.query(
    'SELECT charge_id FROM charges WHERE idempotency_key = ?',
    [idempotencyKey]
  );
  
  if (existing.length > 0) {
    return res.json({ chargeId: existing[0].charge_id });
  }
  
  const charge = await stripe.charges.create({ amount, source: cardToken });
  
  await db.query(
    'INSERT INTO charges (idempotency_key, charge_id) VALUES (?, ?)',
    [idempotencyKey, charge.id]
  );
  
  res.json({ chargeId: charge.id });
});
`;

export const fixedPriceCode = `
app.post('/api/checkout', async (req, res) => {
  const { items } = req.body;
  
  // Retrieve prices from server, never trust client
  let total = 0;
  for (const item of items) {
    const product = await db.query('SELECT price FROM products WHERE id = ?', [item.productId]);
    total += product[0].price * item.quantity;
  }
  
  const charge = await stripe.charges.create({
    amount: total * 100,
    currency: 'usd',
    source: req.body.cardToken
  });
  
  res.json({ orderId: charge.id, total });
});
`;

export const fixedInventoryCode = `
app.post('/api/purchase', async (req, res) => {
  const { productId, quantity } = req.body;
  
  // Atomic update with verification
  const result = await db.query(
    'UPDATE inventory SET quantity = quantity - ? WHERE product_id = ? AND quantity >= ?',
    [quantity, productId, quantity]
  );
  
  if (result.affectedRows === 0) {
    return res.status(400).json({ error: 'Insufficient inventory' });
  }
  
  res.json({ success: true });
});
`;
