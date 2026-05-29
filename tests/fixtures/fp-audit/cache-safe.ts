// CACHE_POISONING FP exhibits. Zero default findings expected.

const cache: Record<string, unknown> = {};

// (1) Cache key derived from a SERVER-side identifier.
function cacheUserProfile(userId: string, value: unknown): void {
  cache[`profile:${userId}`] = value;
}

// (2) Cache key derived from input that has been HASHED.
import crypto from 'crypto';
function cacheByRequestHash(rawKey: string, value: unknown): void {
  const h = crypto.createHash('sha256').update(rawKey).digest('hex');
  cache[`q:${h}`] = value;
}

// (3) cache.set on constant key.
function cacheGlobalConfig(value: unknown): void {
  cache['global:config'] = value;
}

// (4) Read-only cache lookups that mention req.headers do not trigger.
function lookup(req: { headers: Record<string, string> }): unknown {
  const ua = req.headers['user-agent'];
  return cache[`ua-bucket:${ua ? bucket(ua) : 'unknown'}`];
}
function bucket(ua: string): string { return ua.split('/')[0]; }

void cacheUserProfile; void cacheByRequestHash; void cacheGlobalConfig; void lookup;
