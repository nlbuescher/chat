// src/lib/config/security.ts
import 'server-only';
import { z } from 'zod';

export type AuthConfig = Readonly<{
  session: {
    cookieName: string;
    maxAgeMs: number;
    idleTimeoutMs: number;
  };
  rateLimit: {
    loginWindowMs: number;
    loginMaxPerIp: number;
    loginMaxPerUsername: number;
  };
  lockout: {
    threshold: number;
    durationMs: number;
  };
  tokens: {
    resetTtlMs: number;
  };
}>;

// Helpers
const positiveInt = (min = 1) =>
  z.coerce.number().int().min(min).max(Number.MAX_SAFE_INTEGER);

const EnvSchema = z.object({
  // Sessions
  SESSION_COOKIE_NAME: z.string().trim().min(1).default('__Host-sid'),
  SESSION_MAX_AGE_MS: positiveInt(60_000).default(7 * 24 * 60 * 60 * 1000), // >= 1m
  SESSION_IDLE_TIMEOUT_MS: positiveInt(30_000).default(30 * 60 * 1000), // >= 30s

  // Login rate limit
  RATE_LIMIT_LOGIN_WINDOW_MS: positiveInt(1_000).default(60_000),
  RATE_LIMIT_LOGIN_MAX_PER_IP: positiveInt(1).default(10),
  RATE_LIMIT_LOGIN_MAX_PER_USERNAME: positiveInt(1).default(10),

  // Account lockout
  LOCKOUT_THRESHOLD: positiveInt(1).default(5),
  LOCKOUT_DURATION_MS: positiveInt(1_000).default(15 * 60_000),

  // Token TTLs
  RESET_TOKEN_TTL_MS: positiveInt(60_000).default(30 * 60_000),
});

function buildAuthConfig(): AuthConfig {
  const parsed = EnvSchema.parse(process.env);

  // Invariants
  if (parsed.SESSION_IDLE_TIMEOUT_MS > parsed.SESSION_MAX_AGE_MS) {
    throw new Error(
      `Invalid config: SESSION_IDLE_TIMEOUT_MS (${parsed.SESSION_IDLE_TIMEOUT_MS}) must be <= SESSION_MAX_AGE_MS (${parsed.SESSION_MAX_AGE_MS}).`
    );
  }

  // Optional: In production you may enforce __Host- cookie; keep separate task to avoid breaking change.
  // if (process.env.NODE_ENV === 'production' && !parsed.SESSION_COOKIE_NAME.startsWith('__Host-')) {
  //   throw new Error('SESSION_COOKIE_NAME must start with __Host- in production.');
  // }

  const cfg: AuthConfig = Object.freeze({
    session: {
      cookieName: parsed.SESSION_COOKIE_NAME,
      maxAgeMs: parsed.SESSION_MAX_AGE_MS,
      idleTimeoutMs: parsed.SESSION_IDLE_TIMEOUT_MS,
    },
    rateLimit: {
      loginWindowMs: parsed.RATE_LIMIT_LOGIN_WINDOW_MS,
      loginMaxPerIp: parsed.RATE_LIMIT_LOGIN_MAX_PER_IP,
      loginMaxPerUsername: parsed.RATE_LIMIT_LOGIN_MAX_PER_USERNAME,
    },
    lockout: {
      threshold: parsed.LOCKOUT_THRESHOLD,
      durationMs: parsed.LOCKOUT_DURATION_MS,
    },
    tokens: {
      resetTtlMs: parsed.RESET_TOKEN_TTL_MS,
    },
  });

  return cfg;
}

export const authConfig: AuthConfig = buildAuthConfig();
