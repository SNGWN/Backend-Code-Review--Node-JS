// Default-export source helper — caller imports default name.
import { Request } from 'express';
export default function getId(req: Request): string {
  return req.params.id;
}
