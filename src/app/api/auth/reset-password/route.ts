import { NextResponse } from 'next/server';
import prisma, { nowMs, toBigIntMs } from '@/lib/db';
import { resetPasswordSchema } from '@/lib/validation/schemas';
import { hashPassword } from '@/lib/security/hash';
import { hashToken } from '@/lib/security/token';
import { revokeAllUserSessions, withNoStore } from '@/lib/auth/session';

// POST /api/auth/reset-password
export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => null);
    const parsed = resetPasswordSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map(i => ({ path: i.path.join('.'), message: i.message }));
      return withNoStore(NextResponse.json({ error: 'Invalid input', issues }, { status: 400 }));
    }

    const { token, newPassword } = parsed.data;
    const tokenHash = hashToken(token);

    const rec = await prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      select: {
        tokenHash: true,
        userId: true,
        createdAt: true,
        expiresAt: true,
        usedAt: true,
        user: { select: { id: true, isActive: true } },
      },
    });

    const now = nowMs();

    if (!rec || rec.usedAt != null || Number(rec.expiresAt) < now || !rec.user?.isActive) {
      // Do not reveal details
      const res = NextResponse.json({ error: 'Invalid or expired token' }, { status: 400 });
      res.headers.set('Pragma', 'no-cache');
      return withNoStore(res);
    }

    const newHash = await hashPassword(newPassword);
    const nowBig = toBigIntMs(now);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: rec.userId },
        data: {
          passwordHash: newHash,
          passwordUpdatedAt: nowBig,
          failedLoginCount: 0,
          lockedUntil: null,
          updatedAt: nowBig,
        },
      }),
      prisma.passwordResetToken.update({
        where: { tokenHash },
        data: { usedAt: nowBig },
      }),
    ]);

    // Revoke all user sessions after password rotation
    await revokeAllUserSessions(rec.userId);

    const res = NextResponse.json({ ok: true }, { status: 200 });
    res.headers.set('Pragma', 'no-cache');
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: 'Reset password failed' }, { status: 500 }));
  }
}
