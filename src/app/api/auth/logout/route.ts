import { NextResponse } from "next/server";
import {
  readSessionIdFromCookies,
  revokeSession,
  clearSessionCookie,
  withNoStore,
} from "@/lib/auth/session";
import { verifyCsrf, ensureCsrfCookie } from "@/lib/security/csrf";

// POST /api/auth/logout
export async function POST(req: Request) {
  try {
    if (!verifyCsrf(req)) {
      const res = NextResponse.json({ error: "CSRF token missing or invalid" }, { status: 403 });
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }
    const sid = await readSessionIdFromCookies();
    if (sid) {
      await revokeSession(sid);
    }
    const res = NextResponse.json({ ok: true }, { status: 200 });
    clearSessionCookie(res);
    res.headers.set("Pragma", "no-cache");
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: "Logout failed" }, { status: 500 }));
  }
}
