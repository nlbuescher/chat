// src/lib/config/security.ts
import "server-only";
import { z } from "zod";

export type AuthConfig = Readonly<{
  session: {
    cookieName: string;
    maxAgeMs: number;
    idleTimeoutMs: number;
    sameSite: "lax" | "strict" | "none";
    rotationIntervalMs: number;
    maxSessionsPerUser: number;
  };
  csrf: {
    cookieName: string;
    headerName: string;
    sameSite: "lax" | "strict" | "none";
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
    resetMaxPerUser: number;
    resetUserWindowMs: number;
    resetIpMax: number;
    resetIpWindowMs: number;
    devResetLink: boolean;
  };
  network: {
    trustProxy: boolean;
  };
  retention: {
    loginAttemptsMs: number;
    resetRequestsMs: number;
  };
  rotation: {
    rotateOnIpChange: boolean;
    rotateOnUserAgentChange: boolean;
  };
}>;

// Helpers
const positiveInt = (min = 1) => z.coerce.number().int().min(min).max(Number.MAX_SAFE_INTEGER);

const EnvSchema = z.object({
  // Sessions
  SESSION_COOKIE_NAME: z.string().trim().min(1).default("__Host-sid"),
  SESSION_MAX_AGE_MS: positiveInt(60_000).default(7 * 24 * 60 * 60 * 1000), // >= 1m
  SESSION_IDLE_TIMEOUT_MS: positiveInt(30_000).default(30 * 60 * 1000), // >= 30s
  SESSION_SAMESITE: z.enum(["lax", "strict", "none"]).default("strict"),
  SESSION_ROTATION_INTERVAL_MS: positiveInt(60_000).default(12 * 60 * 60 * 1000), // 12h
  SESSION_MAX_SESSIONS_PER_USER: positiveInt(1).default(5),

  // CSRF (double-submit)
  CSRF_COOKIE_NAME: z.string().trim().min(1).default("__Host-csrf"),
  CSRF_HEADER_NAME: z.string().trim().min(1).default("x-csrf-token"),
  CSRF_SAMESITE: z.enum(["lax", "strict", "none"]).default("strict"),

  // Login rate limit
  RATE_LIMIT_LOGIN_WINDOW_MS: positiveInt(1_000).default(60_000),
  RATE_LIMIT_LOGIN_MAX_PER_IP: positiveInt(1).default(10),
  RATE_LIMIT_LOGIN_MAX_PER_USERNAME: positiveInt(1).default(10),

  // Account lockout
  LOCKOUT_THRESHOLD: positiveInt(1).default(5),
  LOCKOUT_DURATION_MS: positiveInt(1_000).default(15 * 60_000),

  // Reset/password tokens and request limiting
  RESET_TOKEN_TTL_MS: positiveInt(60_000).default(30 * 60_000),
  RESET_MAX_PER_USER: positiveInt(1).default(3),
  RESET_WINDOW_MS: positiveInt(60_000).default(15 * 60_000), // per-user window
  RESET_MAX_PER_IP: positiveInt(1).default(30),
  RESET_IP_WINDOW_MS: positiveInt(60_000).default(15 * 60_000),
  FEATURE_DEV_RESET_LINK: z.string().default("false"),

  // Network / proxy trust
  TRUST_PROXY: z.string().default("false"),

  // Retention windows
  RETENTION_LOGIN_ATTEMPTS_MS: positiveInt(60_000).default(30 * 24 * 60 * 60 * 1000), // 30d
  RETENTION_RESET_REQUESTS_MS: positiveInt(60_000).default(30 * 24 * 60 * 60 * 1000), // 30d

  // Session rotation policy
  ROTATE_ON_IP_CHANGE: z.string().default("true"),
  ROTATE_ON_UA_CHANGE: z.string().default("true"),
});

function buildAuthConfig(): AuthConfig {
  const parsed = EnvSchema.parse(process.env);

  // Invariants
  if (parsed.SESSION_IDLE_TIMEOUT_MS > parsed.SESSION_MAX_AGE_MS) {
    throw new Error(
      `Invalid config: SESSION_IDLE_TIMEOUT_MS (${parsed.SESSION_IDLE_TIMEOUT_MS}) must be <= SESSION_MAX_AGE_MS (${parsed.SESSION_MAX_AGE_MS}).`,
    );
  }

  // Enforce __Host- cookie name in production
  if (process.env.NODE_ENV === "production" && !parsed.SESSION_COOKIE_NAME.startsWith("__Host-")) {
    throw new Error("SESSION_COOKIE_NAME must start with __Host- in production.");
  }
  if (process.env.NODE_ENV === "production" && !parsed.CSRF_COOKIE_NAME.startsWith("__Host-")) {
    throw new Error("CSRF_COOKIE_NAME must start with __Host- in production.");
  }

  const cfg: AuthConfig = Object.freeze({
    session: {
      cookieName: parsed.SESSION_COOKIE_NAME,
      maxAgeMs: parsed.SESSION_MAX_AGE_MS,
      idleTimeoutMs: parsed.SESSION_IDLE_TIMEOUT_MS,
      sameSite: parsed.SESSION_SAMESITE,
      rotationIntervalMs: parsed.SESSION_ROTATION_INTERVAL_MS,
      maxSessionsPerUser: parsed.SESSION_MAX_SESSIONS_PER_USER,
    },
    csrf: {
      cookieName: parsed.CSRF_COOKIE_NAME,
      headerName: parsed.CSRF_HEADER_NAME,
      sameSite: parsed.CSRF_SAMESITE,
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
      resetMaxPerUser: parsed.RESET_MAX_PER_USER,
      resetUserWindowMs: parsed.RESET_WINDOW_MS,
      resetIpMax: parsed.RESET_MAX_PER_IP,
      resetIpWindowMs: parsed.RESET_IP_WINDOW_MS,
      devResetLink: (parsed.FEATURE_DEV_RESET_LINK ?? "false").toLowerCase() === "true",
    },
    network: {
      trustProxy: (parsed.TRUST_PROXY ?? "false").toLowerCase() === "true",
    },
    retention: {
      loginAttemptsMs: parsed.RETENTION_LOGIN_ATTEMPTS_MS,
      resetRequestsMs: parsed.RETENTION_RESET_REQUESTS_MS,
    },
    rotation: {
      rotateOnIpChange: (parsed.ROTATE_ON_IP_CHANGE ?? "true").toLowerCase() === "true",
      rotateOnUserAgentChange: (parsed.ROTATE_ON_UA_CHANGE ?? "true").toLowerCase() === "true",
    },
  });

  return cfg;
}

export const authConfig: AuthConfig = buildAuthConfig();
