const queue = {
  publish: (_message: unknown) => {},
  consume: (_handler: (msg: any) => void) => {},
};

const amqpClient = {
  ack: (_msg: unknown) => {},
};

export function queueHandler(req: any): void {
  queue.publish(req.body.event);

  queue.consume((msg: any) => {
    const payload = JSON.parse(msg.body);
    amqpClient.ack(payload);
  });
}
