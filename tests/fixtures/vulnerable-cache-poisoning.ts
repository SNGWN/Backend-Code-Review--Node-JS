const cache = {
  set: (_key: string, _value: unknown) => {},
};

export function cacheHandler(req: any): void {
  cache.set(req.headers.host, req.body.payload);
  cache.set(req.url, { data: req.query.userInput });
}
