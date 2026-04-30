// VULNERABLE: Privilege escalation
import express from 'express';

const app = express();

// ❌ VULNERABLE: Admin function without role check
function deleteAllUsers() {
  // CRITICAL: No check if user is admin
  // Any authenticated user can call this and delete all users
  const result = db.User.deleteAll();
  return result;
}

// ❌ VULNERABLE: Updating user role without permission check
app.put('/api/users/:id/role', (req, res) => {
  const userId = req.params.id;
  const newRole = req.body.role;
  
  // VULNERABLE: No check if requester is admin
  // Regular user can escalate their own role to admin
  const user = db.User.findById(userId);
  user.role = newRole;
  user.permissions = req.body.permissions;
  user.save();
  
  res.json(user);
});

// ❌ VULNERABLE: Creating admin accounts without authorization
app.post('/api/users', (req, res) => {
  const user = new db.User({
    name: req.body.name,
    email: req.body.email,
    role: req.body.role, // User can set their own role!
    isAdmin: req.body.isAdmin, // User can make themselves admin!
  });
  
  user.save();
  res.json(user);
});

// ❌ VULNERABLE: Admin operations in regular endpoint
app.get('/api/admin/settings', (req, res) => {
  // No role check, any authenticated user can access admin settings
  const settings = db.AdminSetting.all();
  res.json(settings);
});
