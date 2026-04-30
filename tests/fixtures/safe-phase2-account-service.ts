import crypto from 'crypto';

type PublicProfile = {
  id: string;
  email: string;
  roles: string[];
};

export function buildSafeProfileResponse(profile: PublicProfile) {
  const correlationId = crypto.randomUUID();

  return {
    correlationId,
    profile: {
      id: profile.id,
      email: profile.email,
      roles: [...profile.roles],
    },
  };
}

export function generateSecureNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function mergeAllowedPreferences(input: { theme?: string; timezone?: string }) {
  return {
    theme: input.theme ?? 'light',
    timezone: input.timezone ?? 'UTC',
  };
}
