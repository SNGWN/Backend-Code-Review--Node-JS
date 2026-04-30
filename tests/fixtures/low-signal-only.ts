import express from 'express';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());

const reportLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
});

app.get('/reports', reportLimiter, (req, res) => {
  const filter = req.query.filter;
  const reportMode = process.env.REPORT_MODE;

  console.log('Error generating report', filter, reportMode);
  res.json({ ok: true });
});

export default app;
