import { NextResponse } from "next/server";
import prisma, { nowMs, toBigIntMs } from "@/lib/db";
import { requestPasswordResetSchema, usernameSchema } from "@/lib/validation/schemas";
import { generateToken } from "@/lib/security/token";
import { withNoStore, getClientInfo } from "@/lib/auth/session";
import { authConfig } from "@/lib/config/security";
import { verifyCsrf, ensureCsrfCookie } from "@/lib/security/csrf";

async function findUserByIdentifier(identifier: string) {
  // Try username first (normalized to lowercase via schema)
  const u = usernameSchema.safeParse(identifier);
  if (u.success) {
    return prisma.user.findUnique({
      where: { username: u.data },
      select: { id: true, username: true, isActive: true },
    });
  }
  // Fallback to email; try both raw and lowercased to be resilient
  const emailLc = identifier.toLowerCase();
  return prisma.user.findFirst({
    where: { OR: [{ email: identifier }, { email: emailLc }] },
    select: { id: true, username: true, isActive: true },
  });
}

// POST /api/auth/request-password-reset
export async function POST(req: Request) {
  try {
    // CSRF protection
    if (!verifyCsrf(req)) {
      const res = NextResponse.json({ error: "CSRF token missing or invalid" }, { status: 403 });
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }
    const body = await req.json().catch(() => null);
    const parsed = requestPasswordResetSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message,
      }));
      const res = NextResponse.json({ error: "Invalid input", issues }, { status: 400 });
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    const {
      resetTtlMs,
      resetMaxPerUser,
      resetUserWindowMs,
      resetIpMax,
      resetIpWindowMs,
      devResetLink,
    } = authConfig.tokens;

    // Per-IP rate limiting (DB-backed, account-agnostic)
    const { ip } = getClientInfo(req);
    const ipKey = ip ?? "unknown";
    const now = nowMs();
    const sinceIp = toBigIntMs(now - resetIpWindowMs);

    const ipCount = await prisma.passwordResetRequest.count({
      where: { ip: ipKey, createdAt: { gte: sinceIp } },
    });
    if (ipCount >= resetIpMax) {
      // Always 200 to avoid enumeration
      const res = NextResponse.json({ ok: true }, { status: 200 });
      res.headers.set("Pragma", "no-cache");
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    const { identifier } = parsed.data;
    const user = await findUserByIdentifier(identifier);

    // Always return 200 to avoid account enumeration
    if (!user || !user.isActive) {
      // Record request for IP window even if user not found
      await prisma.passwordResetRequest.create({
        data: { ip: ipKey, createdAt: toBigIntMs(now) },
      });
      const res = NextResponse.json({ ok: true }, { status: 200 });
      res.headers.set("Pragma", "no-cache");
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    // Per-user rate limit using PasswordResetToken window
    const sinceUser = toBigIntMs(now - resetUserWindowMs);
    const recentCount = await prisma.passwordResetToken.count({
      where: { userId: user.id, createdAt: { gte: sinceUser } },
    });
    if (recentCount >= resetMaxPerUser) {
      await prisma.passwordResetRequest.create({
        data: { ip: ipKey, createdAt: toBigIntMs(now) },
      });
      const res = NextResponse.json({ ok: true }, { status: 200 });
      res.headers.set("Pragma", "no-cache");
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    // Generate token and persist hash
    const { token, hash } = generateToken(32);
    const createdAt = toBigIntMs(now);
    const expiresAt = toBigIntMs(now + resetTtlMs);

    await prisma.$transaction([
      prisma.passwordResetToken.create({
        data: {
          tokenHash: hash,
          userId: user.id,
          createdAt,
          expiresAt,
        },
      }),
      prisma.passwordResetRequest.create({
        data: { ip: ipKey, createdAt },
      }),
    ]);

    // Dev-only: optionally expose reset link (no raw token) when explicitly enabled
    if (process.env["NODE_ENV"] !== "production" && devResetLink) {
      const origin = new URL(req.url).origin;
      const link = `${origin}/reset-password?token=${token}`;
      console.warn("[DEV] Password reset link:", link);
      const res = NextResponse.json({ ok: true, devLink: link }, { status: 200 });
      res.headers.set("Pragma", "no-cache");
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    const res = NextResponse.json({ ok: true }, { status: 200 });
    res.headers.set("Pragma", "no-cache");
    ensureCsrfCookie(req, res);
    return withNoStore(res);
  } catch {
    return withNoStore(
      NextResponse.json({ error: "Request password reset failed" }, { status: 500 }),
    );
  }
}
