const cache = {
  set: (_key: string, _value: unknown) => {},
};

function normalizeCacheKey(rawKey: string): string {
  return `cache-${rawKey.toLowerCase().replace(/[^a-z0-9]/g, '')}`;
}

export function safeCacheHandler(req: any): void {
  const trustedKey = normalizeCacheKey(String(req.params.userId));
  cache.set(trustedKey, req.body.payload);
}
