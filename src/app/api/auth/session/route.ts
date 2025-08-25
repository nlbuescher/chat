import { NextResponse } from "next/server";
import {
  validateAndTouchSession,
  withNoStore,
  applySessionRotationIfNeeded,
} from "@/lib/auth/session";
import { ensureCsrfCookie } from "@/lib/security/csrf";

// GET /api/auth/session
export async function GET(req: Request) {
  try {
    const auth = await validateAndTouchSession(req);
    if (!auth.valid) {
      const res = NextResponse.json({ authenticated: false }, { status: 200 });
      res.headers.set("Pragma", "no-cache");
      // Ensure CSRF cookie exists for clients to fetch and use on subsequent POSTs
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }
    const res = NextResponse.json(
      {
        authenticated: true,
        user: { id: auth.session.user.id, username: auth.session.user.username },
      },
      { status: 200 },
    );
    // If session rotated, set new cookie atomically; also refresh CSRF cookie
    applySessionRotationIfNeeded(res, auth);
    ensureCsrfCookie(req, res);
    res.headers.set("Pragma", "no-cache");
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: "Session check failed" }, { status: 500 }));
  }
}
