import { NextResponse } from "next/server";
import prisma, { nowMs, toBigIntMs } from "@/lib/db";
import { hashPassword } from "@/lib/security/hash";
import { registerSchema } from "@/lib/validation/schemas";
import { withNoStore } from "@/lib/auth/session";
import { verifyCsrf, ensureCsrfCookie } from "@/lib/security/csrf";

// POST /api/auth/register
export async function POST(req: Request) {
  try {
    // CSRF protection (double-submit)
    if (!verifyCsrf(req)) {
      const res = NextResponse.json({ error: "CSRF token missing or invalid" }, { status: 403 });
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }
    const body = await req.json().catch(() => null);

    const parsed = registerSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message,
      }));
      const res = NextResponse.json({ error: "Invalid input", issues }, { status: 400 });
      ensureCsrfCookie(req, res);
      return withNoStore(res);
    }

    const { username, email, password } = parsed.data;

    // Enforce uniqueness
    const [byUsername, byEmail] = await Promise.all([
      prisma.user.findUnique({ where: { username } }),
      email ? prisma.user.findUnique({ where: { email } }) : Promise.resolve(null),
    ]);

    if (byUsername) {
      return withNoStore(NextResponse.json({ error: "Username already taken" }, { status: 409 }));
    }
    if (email && byEmail) {
      return withNoStore(NextResponse.json({ error: "Email already registered" }, { status: 409 }));
    }

    // Hash password
    const passwordHash = await hashPassword(password);
    const now = toBigIntMs(nowMs());

    await prisma.user.create({
      data: {
        username,
        email: email ?? null,
        passwordHash,
        isActive: true,
        failedLoginCount: 0,
        lockedUntil: null,
        lastLoginAt: null,
        passwordUpdatedAt: now,
        createdAt: now,
        updatedAt: now,
      },
    });

    const res = NextResponse.json({ ok: true }, { status: 201 });
    // Refresh CSRF cookie post-registration
    ensureCsrfCookie(req, res);
    return withNoStore(res);
  } catch {
    // Avoid leaking details
    return withNoStore(NextResponse.json({ error: "Registration failed" }, { status: 500 }));
  }
}
