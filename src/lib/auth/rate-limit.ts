// src/lib/auth/rate-limit.ts
import prisma, { nowMs, toBigIntMs } from "@/lib/db";
import { authConfig } from "@/lib/config/security";

export const LOGIN_WINDOW_MS = authConfig.rateLimit.loginWindowMs; // 1 minute default via config
export const LOGIN_MAX_PER_IP = authConfig.rateLimit.loginMaxPerIp;
export const LOGIN_MAX_PER_USERNAME = authConfig.rateLimit.loginMaxPerUsername;

export type RateLimitCheck = {
  allowed: boolean;
  reason?: "ip" | "username";
  ipCount?: number;
  usernameCount?: number;
};

export async function checkLoginRateLimit(
  ip: string | null,
  usernameKey: string | null,
): Promise<RateLimitCheck> {
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
    return { allowed: false, reason: "ip", ipCount, usernameCount };
  }
  if (usernameKey && usernameCount >= LOGIN_MAX_PER_USERNAME) {
    return { allowed: false, reason: "username", ipCount, usernameCount };
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
