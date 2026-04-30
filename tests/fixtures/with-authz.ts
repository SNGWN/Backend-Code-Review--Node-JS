// SECURE: With proper authorization checks
import express from 'express';

const app = express();

// ✓ SECURE: Includes authorization middleware
app.delete(
  '/api/users/:id',
  authMiddleware,
  authorizationMiddleware,
  (req, res) => {
    const userId = req.params.id;
    const result = db.User.deleteById(userId);
    res.json({ success: true });
  }
);

// ✓ SECURE: Verifies ownership before returning data
app.get('/api/users/:id/profile', authMiddleware, (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.id;
  
  // Check ownership
  if (userId !== currentUserId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const user = db.User.findById(userId);
  res.json(user);
});

// ✓ SECURE: Includes role check
app.get('/api/admin/settings', authMiddleware, (req, res) => {
  // Verify admin role
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  const settings = db.AdminSetting.all();
  res.json(settings);
});

// ✓ SECURE: Middleware approach for reusable checks
const verifyResourceOwnership = (req, res, next) => {
  const resourceId = req.params.id;
  const currentUserId = req.user.id;
  
  const resource = db.Resource.findById(resourceId);
  
  if (!resource || resource.userId !== currentUserId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  req.resource = resource;
  next();
};

app.patch(
  '/api/profile/:id',
  authMiddleware,
  verifyResourceOwnership,
  (req, res) => {
    req.resource.email = req.body.email;
    req.resource.save();
    res.json(req.resource);
  }
);
