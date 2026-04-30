import crypto from 'crypto';

type AccountRecord = {
  id: string;
  email: string;
  password: string;
  apiKey: string;
  ssn: string;
};

function md5(value: string): string {
  return crypto.createHash('md5').update(value).digest('hex');
}

function issueResetToken(tokenValue: string): string {
  return tokenValue;
}

function signSession(payload: Record<string, unknown>, options: { key: string }) {
  return { payload, options };
}

export function buildAccountResponse(user: AccountRecord) {
  const passwordDigest = md5(user.password);
  const resetToken = issueResetToken(Math.random().toString(36).slice(2));
  const session = signSession(
    { sub: user.id, passwordDigest },
    { key: 'SuperSecretKey12345' }
  );

  return {
    id: user.id,
    email: user.email,
    password: user.password,
    apiKey: user.apiKey,
    ssn: user.ssn,
    resetToken,
    session,
  };
}
