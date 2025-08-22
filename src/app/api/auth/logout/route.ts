import { NextResponse } from 'next/server';
import { readSessionIdFromCookies, revokeSession, clearSessionCookie, withNoStore } from '@/lib/auth/session';

// POST /api/auth/logout
export async function POST() {
  try {
    const sid = await readSessionIdFromCookies();
    if (sid) {
      await revokeSession(sid);
    }
    const res = NextResponse.json({ ok: true }, { status: 200 });
    clearSessionCookie(res);
    res.headers.set('Pragma', 'no-cache');
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: 'Logout failed' }, { status: 500 }));
  }
}
