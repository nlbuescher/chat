import { NextResponse } from 'next/server';
import prisma, { nowMs, toBigIntMs } from '@/lib/db';
import { requestPasswordResetSchema, usernameSchema } from '@/lib/validation/schemas';
import { generateToken, RESET_TOKEN_TTL_MS } from '@/lib/security/token';
import { withNoStore, getClientInfo } from '@/lib/auth/session';

const RESET_MAX_PER_USER = +(process.env['RESET_MAX_PER_USER'] ?? 3);
const RESET_WINDOW_MS = +(process.env['RESET_WINDOW_MS'] ?? 15 * 60_000); // 15 minutes

// Per-IP limiter for reset requests (best-effort, in-memory)
const RESET_MAX_PER_IP = +(process.env['RESET_MAX_PER_IP'] ?? 30);
const RESET_IP_WINDOW_MS = +(process.env['RESET_IP_WINDOW_MS'] ?? 15 * 60_000);
const RESET_IP_WINDOW = new Map<string, { count: number; resetAt: number }>();

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
    const body = await req.json().catch(() => null);
    const parsed = requestPasswordResetSchema.safeParse(body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map(i => ({ path: i.path.join('.'), message: i.message }));
      return withNoStore(NextResponse.json({ error: 'Invalid input', issues }, { status: 400 }));
    }

    // Per-IP rate limiting for reset requests (does not reveal account existence)
    const { ip } = getClientInfo(req);
    {
      const key = ip ?? 'unknown';
      const now = nowMs();
      const entry = RESET_IP_WINDOW.get(key);
      if (!entry || now > entry.resetAt) {
        RESET_IP_WINDOW.set(key, { count: 1, resetAt: now + RESET_IP_WINDOW_MS });
      } else {
        entry.count += 1;
        if (entry.count > RESET_MAX_PER_IP) {
          const res = NextResponse.json({ ok: true }, { status: 200 });
          res.headers.set('Pragma', 'no-cache');
          return withNoStore(res);
        }
      }
    }

    const { identifier } = parsed.data;
    const user = await findUserByIdentifier(identifier);

    // Always return 200 to avoid account enumeration
    if (!user || !user.isActive) {
      const res = NextResponse.json({ ok: true }, { status: 200 });
      res.headers.set('Pragma', 'no-cache');
      return withNoStore(res);
    }

    // Per-user rate limit using PasswordResetToken window
    const since = toBigIntMs(nowMs() - RESET_WINDOW_MS);
    const recentCount = await prisma.passwordResetToken.count({
      where: { userId: user.id, createdAt: { gte: since } },
    });
    if (recentCount >= RESET_MAX_PER_USER) {
      const res = NextResponse.json({ ok: true }, { status: 200 });
      res.headers.set('Pragma', 'no-cache');
      return withNoStore(res);
    }

    // Generate token and persist hash
    const { token, hash } = generateToken(32);
    const createdAt = toBigIntMs(nowMs());
    const expiresAt = toBigIntMs(nowMs() + RESET_TOKEN_TTL_MS);

    await prisma.passwordResetToken.create({
      data: {
        tokenHash: hash,
        userId: user.id,
        createdAt,
        expiresAt,
      },
    });

    // Dev-only: optionally expose reset link (no raw token) when explicitly enabled
    const enableDevLink = (process.env['FEATURE_DEV_RESET_LINK'] ?? 'false').toLowerCase() === 'true';
    if (process.env['NODE_ENV'] !== 'production' && enableDevLink) {
      const origin = new URL(req.url).origin;
      const link = `${origin}/reset-password?token=${token}`;
      console.warn('[DEV] Password reset link:', link);
      const res = NextResponse.json({ ok: true, devLink: link }, { status: 200 });
      res.headers.set('Pragma', 'no-cache');
      return withNoStore(res);
    }

    const res = NextResponse.json({ ok: true }, { status: 200 });
    res.headers.set('Pragma', 'no-cache');
    return withNoStore(res);
  } catch {
    return withNoStore(NextResponse.json({ error: 'Request password reset failed' }, { status: 500 }));
  }
}
