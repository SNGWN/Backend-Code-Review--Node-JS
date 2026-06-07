// SAFE: the SQL string is a constant and the tainted id is bound as a query parameter.
// Inter-procedural taint must NOT turn this into a false positive.
export function handler(req: any, res: any): void {
  const id = req.params.id;
  (global as any).db.query('SELECT * FROM users WHERE id = ?', [id]);
  res.end();
}
