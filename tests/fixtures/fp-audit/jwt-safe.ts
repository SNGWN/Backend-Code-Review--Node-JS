// JWT-rule FP exhibits. Zero default findings expected.
import jwt from 'jsonwebtoken';

// (1) Credential-named constants that read from env, not literals.
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY ?? '';
const SIGNING_SECRET = process.env.JWT_SECRET ?? '';

// (2) jwt.verify with explicit algorithms — the SAFE form. No "Missing Algorithm" finding.
function verifyToken(token: string): unknown {
  return jwt.verify(token, ENCRYPTION_KEY, { algorithms: ['HS256'] });
}
function verifyTokenWithIssuer(token: string): unknown {
  return jwt.verify(token, SIGNING_SECRET, { algorithms: ['HS256'], issuer: 'auth-service' });
}

// (3) jwt.verify with both algorithm AND expiration check.
function verifyTokenFull(token: string): unknown {
  return jwt.verify(token, SIGNING_SECRET, {
    algorithms: ['HS256'],
    ignoreExpiration: false,
  });
}

// (4) Public key used with RS256 — algorithm-key match is CORRECT, not confusion.
const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----';
function verifyRS256(token: string): unknown {
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
}

// (5) jwt.sign — not a verify-shaped call, must not trigger algorithm-missing rule.
function signLogin(userId: number): string {
  return jwt.sign({ userId }, SIGNING_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
}

void verifyToken; void verifyTokenWithIssuer; void verifyTokenFull; void verifyRS256; void signLogin;
