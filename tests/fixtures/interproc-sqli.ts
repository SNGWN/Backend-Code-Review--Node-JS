// VULNERABLE: tainted value flows THROUGH a helper function before reaching the SQL sink.
// The call site `getId(req)` contains no `req.params` text, so single-expression taint misses
// it; only inter-procedural taint (function-return summary) catches this.
function getId(req: any): string {
  return req.params.id;
}

export function handler(req: any, res: any): void {
  const id = getId(req);
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  (global as any).db.query(sql);
  res.end();
}
