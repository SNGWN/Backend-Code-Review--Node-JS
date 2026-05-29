// ACCESS_CONTROL FP exhibits. Zero default findings expected.
import express from 'express';
const app = express();

// (1) Routes that LOOK sensitive but are auth-protected.
function requireAuth(_req: unknown, _res: unknown, next: () => void) { next(); }
function requireAdmin(_req: unknown, _res: unknown, next: () => void) { next(); }

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  res.json({ deletedId: req.params.id });
});
app.post('/api/admin/role', requireAuth, requireAdmin, (req, res) => {
  res.json({ ok: true });
});

// (2) Resource-by-ID lookups with explicit ownership scope.
app.get('/api/orders/:orderId', requireAuth, async (req, res) => {
  const { orderId } = req.params;
  const userId = (req as { user: { id: string } }).user.id;
  const order = await fakeDb.findOne({ where: { id: orderId, ownerId: userId } });
  if (!order) return res.status(404).json({});
  res.json(order);
});

// (3) Utility functions that LOOK admin-y but operate on local state, not requests.
function deleteCacheKey(key: string): void {
  delete (globalThis as unknown as Record<string, unknown>)[key];
}
function updateBufferTimestamp(buf: { ts?: number }): void { buf.ts = Date.now(); }
function removeStaleEntries(map: Map<string, unknown>): void { map.clear(); }

// (4) Internal admin functions whose body has explicit role check.
function adminPurge(actor: { isAdmin?: boolean }, target: string): boolean {
  if (!actor.isAdmin) throw new Error('forbidden');
  return purgeTarget(target);
}
function purgeTarget(_t: string): boolean { return true; }

// (5) Endpoints that don't actually deal with user-supplied resource IDs.
app.get('/api/stats/summary', requireAuth, (_req, res) => res.json({ counts: 0 }));

// (6) findById with non-tainted (constant) ID.
app.get('/api/me', requireAuth, async (_req, res) => {
  const me = await fakeDb.findById('me');
  res.json(me);
});

const fakeDb = {
  findOne: async (_q: unknown) => null,
  findById: async (_id: string) => ({ id: 'me' }),
};

void deleteCacheKey; void updateBufferTimestamp; void removeStaleEntries; void adminPurge;

export default app;
