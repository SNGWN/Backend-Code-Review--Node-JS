import express, { Request, Response } from 'express';
import logger from './logger';

const router = express.Router();

// VULNERABILITY 1: Sensitive data in logs
router.post('/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  
  logger.log(`Login attempt for user: ${username} with password: ${password}`);
  logger.info(`User credentials: username=${username}, pwd=${password}`);
  console.log('Login:', { username, password });
  
  const user = authenticate(username, password);
  res.json(user);
});

// VULNERABILITY 2: API key and token logging
router.post('/payment', (req: Request, res: Response) => {
  const apiKey = req.headers['x-api-key'];
  const token = req.headers.authorization;
  
  console.log('API Key received:', apiKey);
  console.log('Bearer token:', token);
  logger.debug(`Processing payment with token: ${token}`);
  
  const result = processPayment(req.body);
  res.json(result);
});

// VULNERABILITY 3: Inappropriate log level for errors
router.post('/delete', (req: Request, res: Response) => {
  try {
    const id = req.params.id;
    database.delete(id);
    console.log('Record deleted successfully');
  } catch (error) {
    console.log('Error deleting record: ' + error.message);
  }
  res.json({ deleted: true });
});

// VULNERABILITY 4: Log injection risk
router.get('/data', (req: Request, res: Response) => {
  const filter = req.query.filter;
  const userInput = req.body.input;
  
  logger.info(`Fetching data with filter: ${filter}`);
  console.log(`User search: ${userInput}`);
  logger.warn(`Query from user: ${req.body.query}`);
  
  const data = database.fetch(filter);
  res.json(data);
});

// VULNERABILITY 5: Missing logs on critical operations
router.post('/admin/assign-role', (req: Request, res: Response) => {
  const userId = req.body.userId;
  const role = req.body.role;
  
  database.updateUserRole(userId, role);
  res.json({ success: true });
});

// VULNERABILITY 6: Sensitive data exposure in logs
router.post('/credit-card', (req: Request, res: Response) => {
  const creditCard = req.body.creditCard;
  const ssn = req.body.ssn;
  const email = req.body.email;
  
  logger.info(`Processing payment for: ${email}, SSN: ${ssn}, Card: ${creditCard}`);
  console.log({ creditCard, ssn, email });
  
  res.json({ processed: true });
});

export default router;
