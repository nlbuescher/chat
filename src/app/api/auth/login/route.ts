import { NextResponse } from "next/server";
import prisma, { nowMs, toBigIntMs } from "@/lib/db";
import { loginSchema } from "@/lib/validation/schemas";
import { verifyPassword, hashPassword } from "@/lib/security/hash";
import { checkLoginRateLimit, recordLoginAttempt, LOGIN_WINDOW_MS } from "@/lib/auth/rate-limit";
import { isLocked, recordFailedLogin, recordSuccessfulLogin } from "@/lib/auth/lockout";
import { createSession, setSessionCookie, withNoStore, getClientInfo } from "@/lib/auth/session";

// POST /api/auth/login
export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => null);
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message,
      }));
      return withNoStore(NextResponse.json({ error: "Invalid input", issues }, { status: 400 }));
    }

    const { username, password } = parsed.data;
    const { ip } = getClientInfo(req);
    const usernameKey = username;

    const rl = await checkLoginRateLimit(ip, usernameKey);
    if (!rl.allowed) {
      await recordLoginAttempt({ ip, usernameKey, success: false });
      const res = NextResponse.json(
        { error: "Too many attempts, try again later" },
        { status: 429 },
      );
      res.headers.set("Retry-After", String(Math.ceil(LOGIN_WINDOW_MS / 1000)));
      return withNoStore(res);
    }

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      await recordLoginAttempt({ ip, usernameKey, success: false });
      return withNoStore(NextResponse.json({ error: "Invalid credentials" }, { status: 401 }));
    }

    if (!user.isActive) {
      await recordLoginAttempt({ ip, usernameKey, success: false });
      const res = NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
      return withNoStore(res);
    }

    const lock = isLocked(user.lockedUntil);
    if (lock.locked) {
      await recordLoginAttempt({ ip, usernameKey, success: false });
      const res = NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
      res.headers.set("Retry-After", String(Math.ceil(lock.remainingMs / 1000)));
      return withNoStore(res);
    }

    const { valid, needsRehash } = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      await recordLoginAttempt({ ip, usernameKey, success: false });
      const fail = await recordFailedLogin({
        id: user.id,
        failedLoginCount: user.failedLoginCount,
        lockedUntil: user.lockedUntil,
      });
      if (fail.locked) {
        const res = NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
        res.headers.set("Retry-After", String(Math.ceil(fail.remainingMs / 1000)));
        return withNoStore(res);
      }
      const res = NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
      return withNoStore(res);
    }

    if (needsRehash) {
      const newHash = await hashPassword(password);
      const now = toBigIntMs(nowMs());
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newHash, passwordUpdatedAt: now, updatedAt: now },
      });
    }

    await recordSuccessfulLogin(user.id);
    const session = await createSession(user.id, req);
    const res = NextResponse.json({ ok: true }, { status: 200 });
    setSessionCookie(session.id, res);
    res.headers.set("Pragma", "no-cache");
    await recordLoginAttempt({ ip, usernameKey, success: true });
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: "Login failed" }, { status: 500 }));
  }
}
