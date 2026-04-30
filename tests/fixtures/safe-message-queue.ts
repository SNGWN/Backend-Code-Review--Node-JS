const queue = {
  publish: (_message: unknown) => {},
  consume: (_handler: (msg: any) => void) => {},
};

function sign(payload: unknown): { payload: unknown; signature: string } {
  return { payload, signature: 'hmac-signature' };
}

function verify(message: { signature: string }): boolean {
  return Boolean(message.signature);
}

function validate(message: { payload: unknown }): boolean {
  return message.payload !== undefined;
}

export function safeQueueHandler(req: any): void {
  queue.publish(sign(req.body.event));

  queue.consume((msg: any) => {
    if (!verify(msg) || !validate(msg)) {
      return;
    }
    const payload = JSON.parse(msg.body);
    return payload;
  });
}
