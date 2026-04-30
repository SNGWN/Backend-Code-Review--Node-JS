const eventBus = {
  on: (_event: string, _handler: (event: any) => void) => {},
  emit: (_event: string, _payload: unknown) => {},
};

export function registerHandlers(req: any): void {
  eventBus.on('order.created', (event: any) => {
    const data = req.body;
    const payload = event.payload || data;
    processEvent(payload);
  });

  eventBus.emit(req.query.eventName, req.body.payload);
}

function processEvent(_payload: unknown): void {}
