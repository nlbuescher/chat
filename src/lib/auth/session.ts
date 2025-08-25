// src/lib/auth/session.ts
import "server-only";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { nanoid } from "nanoid";
import prisma, { nowMs, toBigIntMs, fromBigIntMs } from "@/lib/db";
import { authConfig } from "@/lib/config/security";

const COOKIE_NAME = authConfig.session.cookieName;
const SESSION_MAX_AGE_MS = authConfig.session.maxAgeMs; // default via config
const SESSION_IDLE_TIMEOUT_MS = authConfig.session.idleTimeoutMs; // default via config
const SESSION_SAME_SITE = authConfig.session.sameSite;
const SESSION_ROTATION_INTERVAL_MS = authConfig.session.rotationIntervalMs;
const SESSION_MAX_SESSIONS_PER_USER = authConfig.session.maxSessionsPerUser;

type ClientInfo = {
  ip: string | null;
  userAgent: string | null;
};

export function getClientInfo(req: Request | NextRequest): ClientInfo {
  // Prefer platform-provided IP, then CDN/proxy headers, then XFF chain
  const headers = req.headers;

  let ip: string | null = null;
  const anyReq = req as { ip?: string | null };
  if (typeof anyReq?.ip === "string" && anyReq.ip) {
    ip = anyReq.ip;
  } else {
    ip =
      headers.get("x-vercel-ip") ||
      headers.get("cf-connecting-ip") ||
      headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      headers.get("x-real-ip") ||
      null;
  }

  const userAgent = headers.get("user-agent");
  return { ip, userAgent };
}

export async function createSession(userId: number, req: Request | NextRequest) {
  const id = nanoid(36);
  const now = nowMs();
  const { ip, userAgent } = getClientInfo(req);
  const created = await prisma.session.create({
    data: {
      id,
      userId,
      createdAt: toBigIntMs(now),
      lastUsedAt: toBigIntMs(now),
      expiresAt: toBigIntMs(now + SESSION_MAX_AGE_MS),
      ip,
      userAgent: userAgent ?? undefined,
    },
    select: { id: true, userId: true, expiresAt: true, lastUsedAt: true },
  });

  // Enforce per-user concurrent session cap (evict oldest)
  try {
    const count = await prisma.session.count({ where: { userId } });
    if (count > SESSION_MAX_SESSIONS_PER_USER) {
      const excess = count - SESSION_MAX_SESSIONS_PER_USER;
      const old = await prisma.session.findMany({
        where: { userId, NOT: { id } },
        orderBy: [{ lastUsedAt: "asc" }, { createdAt: "asc" }],
        take: excess,
        select: { id: true },
      });
      if (old.length > 0) {
        await prisma.session.deleteMany({ where: { id: { in: old.map((o) => o.id) } } });
      }
    }
  } catch {
    // best-effort eviction; ignore failures
  }

  return created;
}

export async function getSession(sessionId: string) {
  const s = await prisma.session.findUnique({
    where: { id: sessionId },
    select: {
      id: true,
      userId: true,
      createdAt: true,
      lastUsedAt: true,
      expiresAt: true,
      ip: true,
      userAgent: true,
      user: { select: { id: true, username: true, isActive: true, lockedUntil: true } },
    },
  });
  return s;
}

export function setSessionCookie(id: string, res: NextResponse) {
  const secure = true; // __Host- cookies must be Secure
  // Max-Age equals absolute lifetime; idle timeout enforced server-side
  res.cookies.set(COOKIE_NAME, id, {
    httpOnly: true,
    secure,
    sameSite: SESSION_SAME_SITE,
    path: "/",
    maxAge: Math.floor(SESSION_MAX_AGE_MS / 1000),
    priority: "high",
  });
}

export function clearSessionCookie(res: NextResponse) {
  res.cookies.set(COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: SESSION_SAME_SITE,
    path: "/",
    expires: new Date(0),
  });
}

export async function readSessionIdFromCookies(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get(COOKIE_NAME)?.value ?? null;
}

export async function validateAndTouchSession(req: Request | NextRequest) {
  const id = await readSessionIdFromCookies();
  if (!id) return { valid: false as const, reason: "missing" as const };

  const s = await getSession(id);
  if (!s) return { valid: false as const, reason: "not_found" as const };

  const now = nowMs();
  const expiresAt = fromBigIntMs(s.expiresAt);
  const lastUsedAt = fromBigIntMs(s.lastUsedAt);

  if (expiresAt !== null && now > expiresAt) {
    // Expired absolutely
    await prisma.session.delete({ where: { id } }).catch(() => {});
    return { valid: false as const, reason: "expired" as const };
  }

  // Idle timeout check
  if (lastUsedAt !== null && now - lastUsedAt > SESSION_IDLE_TIMEOUT_MS) {
    await prisma.session.delete({ where: { id } }).catch(() => {});
    return { valid: false as const, reason: "idle_timeout" as const };
  }

  if (!s.user.isActive) {
    return { valid: false as const, reason: "inactive" as const };
  }
  const lockedUntil = fromBigIntMs(s.user.lockedUntil);
  if (lockedUntil && now < lockedUntil) {
    return { valid: false as const, reason: "locked" as const };
  }

  // Rotation policy
  const { ip, userAgent } = getClientInfo(req);
  const createdAt = fromBigIntMs(s.createdAt);
  const rotateDueToAge = createdAt !== null && now - createdAt >= SESSION_ROTATION_INTERVAL_MS;
  const rotateDueToUA = (s.userAgent ?? null) !== (userAgent ?? null);
  const rotateDueToIP = (s.ip ?? null) !== (ip ?? null);

  if (rotateDueToAge || rotateDueToUA || rotateDueToIP) {
    const newSession = await createSession(s.userId, req);
    await prisma.session.delete({ where: { id } }).catch(() => {});
    return {
      valid: true as const,
      session: { ...newSession, user: s.user },
      rotated: true as const,
      rotatedFrom: id,
    };
  }

  // Touch lastUsedAt after checks
  await prisma.session.update({
    where: { id },
    data: { lastUsedAt: toBigIntMs(now) },
  });

  return { valid: true as const, session: s, rotated: false as const };
}

export async function revokeSession(id: string) {
  await prisma.session.delete({ where: { id } }).catch(() => {});
}

export async function revokeAllUserSessions(userId: number, exceptId?: string) {
  if (exceptId) {
    await prisma.session.deleteMany({ where: { userId, NOT: { id: exceptId } } });
  } else {
    await prisma.session.deleteMany({ where: { userId } });
  }
}

export function withNoStore(resp: NextResponse) {
  resp.headers.set("Cache-Control", "no-store, max-age=0, must-revalidate");
  resp.headers.set("Pragma", "no-cache");
  resp.headers.set("Expires", "0");
  resp.headers.set("X-Content-Type-Options", "nosniff");
  resp.headers.set("Referrer-Policy", "no-referrer");
  resp.headers.set("X-Frame-Options", "DENY");
  return resp;
}

export async function pruneExpiredAuthArtifacts() {
  const now = nowMs();
  const nowBig = toBigIntMs(now);
  await prisma.session.deleteMany({ where: { expiresAt: { lt: nowBig } } });
  await prisma.passwordResetToken.deleteMany({
    where: {
      OR: [{ expiresAt: { lt: nowBig } }, { usedAt: { not: null } }],
    },
  });
}
