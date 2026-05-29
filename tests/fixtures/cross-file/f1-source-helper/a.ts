import { Request } from 'express';
// Exported helper that returns user-controlled data. The cross-file ProjectContext
// flags this so callers in other files treat the return value as tainted.
export function getId(req: Request): string {
  return req.params.id;
}
