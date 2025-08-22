import { NextResponse } from 'next/server';
import prisma, { nowMs, toBigIntMs } from '@/lib/db';
import { changePasswordSchema } from '@/lib/validation/schemas';
import { verifyPassword, hashPassword } from '@/lib/security/hash';
import {
  validateAndTouchSession,
  revokeAllUserSessions,
  setSessionCookie,
  withNoStore,
} from '@/lib/auth/session';

// POST /api/auth/change-password
export async function POST(req: Request) {
  try {
    // Require valid session
    const auth = await validateAndTouchSession();
    if (!auth.valid) {
      const status =
        auth.reason === 'missing' ? 401 :
        auth.reason === 'not_found' ? 401 :
        auth.reason === 'expired' ? 401 :
        auth.reason === 'idle_timeout' ? 401 :
        auth.reason === 'inactive' ? 403 :
        auth.reason === 'locked' ? 423 : 401;
      return withNoStore(NextResponse.json({ error: 'Unauthorized' }, { status }));
    }

    const body = await req.json().catch(() => null);
    const parsed = changePasswordSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map(i => ({ path: i.path.join('.'), message: i.message }));
      return withNoStore(NextResponse.json({ error: 'Invalid input', issues }, { status: 400 }));
    }

    const { currentPassword, newPassword } = parsed.data;
    const userId = auth.session.userId;

    // Fetch current password hash
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, passwordHash: true, isActive: true },
    });

    if (!user || !user.isActive) {
      return withNoStore(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }));
    }

    const { valid } = await verifyPassword(currentPassword, user.passwordHash);
    if (!valid) {
      return withNoStore(NextResponse.json({ error: 'Current password is incorrect' }, { status: 400 }));
    }

    const newHash = await hashPassword(newPassword);
    const now = toBigIntMs(nowMs());

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: newHash,
        passwordUpdatedAt: now,
        // Clear any residual lock state on a successful credential rotation
        failedLoginCount: 0,
        lockedUntil: null,
        updatedAt: now,
      },
    });

    // Revoke all other sessions to enforce re-auth elsewhere
    await revokeAllUserSessions(user.id, auth.session.id);

    // Refresh cookie to reset Max-Age for current session
    const res = NextResponse.json({ ok: true }, { status: 200 });
    setSessionCookie(auth.session.id, res);
    res.headers.set('Pragma', 'no-cache');
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: 'Change password failed' }, { status: 500 }));
  }
}
