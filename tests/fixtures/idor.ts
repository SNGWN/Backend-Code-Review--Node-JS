// VULNERABLE: IDOR examples
import express from 'express';

const app = express();

// ❌ VULNERABLE: Direct object reference without authorization
app.get('/api/documents/:docId', (req, res) => {
  const docId = req.params.docId;
  
  // VULNERABLE: findById directly uses user-supplied ID
  const doc = db.Document.findById(docId);
  
  if (!doc) {
    return res.status(404).json({ error: 'Document not found' });
  }
  
  // MISSING: Check if req.user.id == doc.ownerId
  // Attacker can access any document by changing docId
  res.json(doc);
});

// ❌ VULNERABLE: Updating resource without authorization check
app.patch('/api/documents/:docId', (req, res) => {
  const docId = req.params.docId;
  const doc = db.Document.findById(docId);
  
  // VULNERABLE: No ownership verification
  doc.title = req.body.title;
  doc.content = req.body.content;
  doc.save();
  
  res.json(doc);
});

// ❌ VULNERABLE: Downloading sensitive files
app.get('/api/files/:fileId/download', (req, res) => {
  const fileId = req.params.fileId;
  
  // VULNERABLE: findById directly returns any file
  const file = db.File.findById(fileId);
  
  // MISSING: Authorization check
  // Attacker downloads any file in the system
  res.download(file.path);
});

// ❌ VULNERABLE: Accessing user data
app.get('/api/users/:userId/orders', (req, res) => {
  const userId = req.params.userId;
  
  // VULNERABLE: Returns orders for any user ID
  const orders = db.Order.where({ userId }).all();
  
  // MISSING: Check if req.user.id == userId
  res.json(orders);
});
