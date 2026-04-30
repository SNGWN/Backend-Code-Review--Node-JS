import express, { Request, Response } from 'express';

const router = express.Router();

// VULNERABILITY 1: Missing parameter validation
router.get('/users/:id/posts/:postId', (req: Request, res: Response) => {
  const userId = req.params.id;
  const postId = req.params.postId;
  
  const post = database.query(`SELECT * FROM posts WHERE id = ${postId} AND user_id = ${userId}`);
  res.json(post);
});

// VULNERABILITY 2: Missing query parameter validation
router.get('/search', (req: Request, res: Response) => {
  const query = req.query.q;
  const limit = req.query.limit;
  const offset = req.query.offset;
  
  const results = database.search(query, limit, offset);
  res.json(results);
});

// VULNERABILITY 3: Missing body validation
router.post('/register', (req: Request, res: Response) => {
  const { username, email, password } = req.body;
  
  const user = {
    username,
    email,
    password,
    created_at: new Date(),
  };
  
  database.save(user);
  res.json({ success: true });
});

// VULNERABILITY 4: Unvalidated input used in database query
router.post('/filter', (req: Request, res: Response) => {
  const filterField = req.body.field;
  const filterValue = req.body.value;
  
  const items = database.query(`SELECT * FROM items WHERE ${filterField} = '${filterValue}'`);
  res.json(items);
});

// VULNERABILITY 5: Missing sanitization
router.post('/comment', (req: Request, res: Response) => {
  const comment = req.body.text;
  
  const saved = database.save({ text: comment });
  res.json(saved);
});

// VULNERABILITY 6: Direct field assignment without whitelisting
router.put('/settings/:id', (req: Request, res: Response) => {
  const settings = database.getSettings(req.params.id);
  
  for (const key in req.body) {
    settings[key] = req.body[key];
  }
  
  database.save(settings);
  res.json(settings);
});

export default router;
