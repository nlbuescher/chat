// src/lib/auth/rate-limit.ts
import prisma, { nowMs, toBigIntMs } from '../db';

export const LOGIN_WINDOW_MS = +(process.env.RATE_LIMIT_LOGIN_WINDOW_MS ?? 60_000); // 1 minute
export const LOGIN_MAX_PER_IP = +(process.env.RATE_LIMIT_LOGIN_MAX_PER_IP ?? 10);
export const LOGIN_MAX_PER_USERNAME = +(process.env.RATE_LIMIT_LOGIN_MAX_PER_USERNAME ?? 10);

export type RateLimitCheck = {
  allowed: boolean;
  reason?: 'ip' | 'username';
  ipCount?: number;
  usernameCount?: number;
};

export async function checkLoginRateLimit(ip: string | null, usernameKey: string | null): Promise<RateLimitCheck> {
  const since = toBigIntMs(nowMs() - LOGIN_WINDOW_MS);

  const [ipCount, usernameCount] = await Promise.all([
    ip
      ? prisma.loginAttempt.count({
          where: {
            ip,
            createdAt: { gte: since },
          },
        })
      : Promise.resolve(0),
    usernameKey
      ? prisma.loginAttempt.count({
          where: {
            usernameKey,
            createdAt: { gte: since },
          },
        })
      : Promise.resolve(0),
  ]);

  if (ip && ipCount >= LOGIN_MAX_PER_IP) {
    return { allowed: false, reason: 'ip', ipCount, usernameCount };
  }
  if (usernameKey && usernameCount >= LOGIN_MAX_PER_USERNAME) {
    return { allowed: false, reason: 'username', ipCount, usernameCount };
  }
  return { allowed: true, ipCount, usernameCount };
}

export async function recordLoginAttempt(params: {
  ip: string | null;
  usernameKey: string | null;
  success: boolean;
}) {
  const { ip, usernameKey, success } = params;
  await prisma.loginAttempt.create({
    data: {
      ip: ip ?? undefined,
      usernameKey: usernameKey ?? undefined,
      createdAt: toBigIntMs(nowMs()),
      success,
    },
  });
}
