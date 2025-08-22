// src/lib/auth/lockout.ts
import prisma, { nowMs, toBigIntMs, fromBigIntMs } from '@/lib/db';

export const DEFAULT_LOCKOUT_THRESHOLD = +(process.env.LOCKOUT_THRESHOLD ?? 5);
export const DEFAULT_LOCKOUT_DURATION_MS = +(process.env.LOCKOUT_DURATION_MS ?? 15 * 60_000);

type LockoutSettings = {
  threshold: number;
  durationMs: number;
};

export type LockoutStatus = {
  locked: boolean;
  remainingMs: number;
};

export function getLockoutSettings(): LockoutSettings {
  const threshold = Number.isFinite(DEFAULT_LOCKOUT_THRESHOLD) ? DEFAULT_LOCKOUT_THRESHOLD : 5;
  const durationMs = Number.isFinite(DEFAULT_LOCKOUT_DURATION_MS) ? DEFAULT_LOCKOUT_DURATION_MS : 15 * 60_000;
  return { threshold, durationMs };
}

export function isLocked(lockedUntil: bigint | null | undefined): LockoutStatus {
  if (!lockedUntil) return { locked: false, remainingMs: 0 };
  const now = nowMs();
  // lockedUntil was checked above; assert and fallback to now to satisfy TS
  const until = fromBigIntMs(lockedUntil as bigint) ?? now;
  const remaining = until - now;
  if (remaining > 0) {
    return { locked: true, remainingMs: remaining };
  }
  return { locked: false, remainingMs: 0 };
}

export async function recordFailedLogin(user: { id: number; failedLoginCount: number; lockedUntil: bigint | null | undefined; }): Promise<LockoutStatus> {
  const status = isLocked(user.lockedUntil);
  if (status.locked) {
    // Keep lock; don't modify counters while locked
    return status;
  }

  const { threshold, durationMs } = getLockoutSettings();
  const newCount = (user.failedLoginCount ?? 0) + 1;

  if (newCount >= threshold) {
    const until = toBigIntMs(nowMs() + durationMs);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginCount: 0,
        lockedUntil: until,
        updatedAt: toBigIntMs(nowMs()),
      },
    });
    return { locked: true, remainingMs: durationMs };
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      failedLoginCount: newCount,
      updatedAt: toBigIntMs(nowMs()),
    },
  });

  return { locked: false, remainingMs: 0 };
}

export async function recordSuccessfulLogin(userId: number) {
  await prisma.user.update({
    where: { id: userId },
    data: {
      failedLoginCount: 0,
      lockedUntil: null,
      lastLoginAt: toBigIntMs(nowMs()),
      updatedAt: toBigIntMs(nowMs()),
    },
  });
}
