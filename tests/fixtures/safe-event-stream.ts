const eventBus = {
  on: (_event: string, _handler: (event: any) => void) => {},
  emit: (_event: string, _payload: unknown) => {},
};

const ALLOWED_EVENTS: Record<string, string> = {
  order_created: 'order.created',
};

function validate(event: any): boolean {
  return Boolean(event?.payload);
}

export function safeEventHandlers(req: any): void {
  eventBus.on(`tenant:${req.user.tenantId}:order.created`, (event: any) => {
    if (!validate(event)) {
      return;
    }
    return event.payload;
  });

  const eventName = ALLOWED_EVENTS.order_created;
  eventBus.emit(eventName, req.body.payload);
}
