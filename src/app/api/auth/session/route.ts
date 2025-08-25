import { NextResponse } from "next/server";
import { validateAndTouchSession, withNoStore, setSessionCookie } from "@/lib/auth/session";

// GET /api/auth/session
export async function GET(req: Request) {
  try {
    const auth = await validateAndTouchSession(req);
    if (!auth.valid) {
      const res = NextResponse.json({ authenticated: false }, { status: 200 });
      res.headers.set("Pragma", "no-cache");
      return withNoStore(res);
    }
    const res = NextResponse.json(
      {
        authenticated: true,
        user: { id: auth.session.user.id, username: auth.session.user.username },
      },
      { status: 200 },
    );
    if ((auth as any).rotated) {
      setSessionCookie(auth.session.id, res);
    }
    res.headers.set("Pragma", "no-cache");
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: "Session check failed" }, { status: 500 }));
  }
}
