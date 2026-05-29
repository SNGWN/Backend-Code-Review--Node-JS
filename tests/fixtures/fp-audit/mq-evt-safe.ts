// MESSAGE_QUEUE + EVENT_STREAM FP exhibits. Zero default findings expected.

const queue = {
  publish: (_payload: unknown) => {},
  consume: (_handler: (msg: unknown) => void) => {},
  on: (_event: string, _handler: (...args: unknown[]) => void) => {},
};

// (1) Queue consumer that validates payload via joi/zod before JSON.parse.
import { z } from 'zod';
const messageSchema = z.object({ id: z.string(), payload: z.unknown() });

queue.consume((msg: unknown) => {
  const validated = messageSchema.parse(msg);
  console.log('processing', validated.id);
});

// (2) Publish path signs payload before send.
function sign(p: unknown): { p: unknown; sig: string } {
  return { p, sig: 'hmac-' + JSON.stringify(p).length };
}
function publishSafe(payload: unknown): void {
  queue.publish(sign(payload));
}

// (3) EventEmitter on safe domain events (no req.body source).
queue.on('order.created', (orderId: unknown) => {
  console.log('order created', orderId);
});

// (4) Event subscription scoped by tenant.
queue.on('user.updated', (...args: unknown[]) => {
  const [event] = args as [{ tenantId: string; userId: string }];
  if (!event.tenantId) return;
  process({ tenantId: event.tenantId, userId: event.userId });
});
function process(_e: { tenantId: string; userId: string }): void {}

void publishSafe;
