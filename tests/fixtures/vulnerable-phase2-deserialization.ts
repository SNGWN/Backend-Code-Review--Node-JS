import express from 'express';

const app = express();
app.use(express.json());

app.post('/imports/profile', (req, res) => {
  const payload = req.body.payload;
  const parsed = JSON.parse(payload);
  const hydratedProfile = eval(req.body.expression);
  const session = { tenantId: req.body.tenantId };

  Object.assign(session, req.body.overrides);

  const projectedProfile = {
    ...req.body.preferences,
    tenantId: req.body.tenantId,
  };

  res.json({ parsed, hydratedProfile, projectedProfile });
});

export default app;
