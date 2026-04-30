import express, { Request, Response } from 'express';

const router = express.Router();

// VULNERABILITY 1: Direct Object.assign with user input
router.post('/users', (req: Request, res: Response) => {
  const newUser = {};
  Object.assign(newUser, req.body);
  
  database.save(newUser);
  res.json(newUser);
});

// VULNERABILITY 2: Spread operator with user input
router.post('/products', (req: Request, res: Response) => {
  const product = {
    ...req.body,
    created_at: new Date(),
  };
  
  database.save(product);
  res.json(product);
});

// VULNERABILITY 3: Direct property assignment without whitelisting
router.put('/profiles/:id', (req: Request, res: Response) => {
  const profile = database.get(req.params.id);
  
  for (const key in req.body) {
    profile[key] = req.body[key];
  }
  
  database.save(profile);
  res.json(profile);
});

// VULNERABILITY 4: Prototype pollution risk
router.post('/settings', (req: Request, res: Response) => {
  const settings = {};
  
  for (const key in req.body) {
    if (key === '__proto__' || key === 'constructor') {
      continue;
    }
    settings[key] = req.body[key];
  }
  
  Object.assign(settings, req.body);
  
  res.json(settings);
});

// VULNERABILITY 5: Constructor property assignment
router.post('/config', (req: Request, res: Response) => {
  const config = {
    name: req.body.name,
    version: req.body.version,
    constructor: req.body.constructor,
    prototype: req.body.prototype,
  };
  
  database.save(config);
  res.json(config);
});

// VULNERABILITY 6: Object.entries with direct assignment
router.put('/data/:id', (req: Request, res: Response) => {
  const item = database.get(req.params.id);
  const data = req.body;
  
  Object.entries(data).forEach(([key, value]) => {
    item[key] = value;
  });
  
  database.save(item);
  res.json(item);
});

// VULNERABILITY 7: Direct assignment of all properties
router.post('/sync', (req: Request, res: Response) => {
  const localData = {};
  const remoteData = req.body;
  
  for (const prop in remoteData) {
    localData[prop] = remoteData[prop];
  }
  
  database.sync(localData);
  res.json({ synced: true });
});

export default router;
