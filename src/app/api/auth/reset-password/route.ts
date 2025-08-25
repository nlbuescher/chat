import { NextResponse } from "next/server";
import prisma, { nowMs, toBigIntMs } from "@/lib/db";
import { resetPasswordSchema } from "@/lib/validation/schemas";
import { hashPassword } from "@/lib/security/hash";
import { hashToken } from "@/lib/security/token";
import { revokeAllUserSessions, withNoStore } from "@/lib/auth/session";
import { verifyCsrf, ensureCsrfCookie } from "@/lib/security/csrf";

// POST /api/auth/reset-password
export async function POST(req: Request) {
  try {
    // CSRF protection
    if (!verifyCsrf(req)) {
      const res = NextResponse.json({ error: "CSRF token missing or invalid" }, { status: 403 });
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    const body = await req.json().catch(() => null);
    const parsed = resetPasswordSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message,
      }));
      return withNoStore(NextResponse.json({ error: "Invalid input", issues }, { status: 400 }));
    }

    const { token, newPassword } = parsed.data;
    const tokenHash = hashToken(token);

    const now = nowMs();
    const nowBig = toBigIntMs(now);

    // Hash new password (argon2id)
    const newHash = await hashPassword(newPassword);

    // Atomic token consumption to prevent double use
    let userIdToRevoke: number | null = null;
    try {
      await prisma.$transaction(async (tx) => {
        const updated = await tx.passwordResetToken.updateMany({
          where: { tokenHash, usedAt: null, expiresAt: { gte: nowBig } },
          data: { usedAt: nowBig },
        });
        if (updated.count !== 1) {
          throw new Error("invalid_or_expired");
        }

        const rec = await tx.passwordResetToken.findUnique({
          where: { tokenHash },
          select: { userId: true, user: { select: { isActive: true } } },
        });
        if (!rec?.user?.isActive) {
          throw new Error("invalid_or_expired");
        }

        userIdToRevoke = rec.userId;

        await tx.user.update({
          where: { id: rec.userId },
          data: {
            passwordHash: newHash,
            passwordUpdatedAt: nowBig,
            failedLoginCount: 0,
            lockedUntil: null,
            updatedAt: nowBig,
          },
        });
      });
    } catch {
      const res = NextResponse.json({ error: "Invalid or expired token" }, { status: 400 });
      res.headers.set("Pragma", "no-cache");
      return withNoStore(res);
    }

    // Revoke all user sessions after password rotation
    if (userIdToRevoke != null) {
      await revokeAllUserSessions(userIdToRevoke);
    }

    const res = NextResponse.json({ ok: true }, { status: 200 });
    res.headers.set("Pragma", "no-cache");
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: "Reset password failed" }, { status: 500 }));
  }
}
