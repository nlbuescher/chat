// src/lib/security/csrf.ts
import "server-only";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { authConfig } from "@/lib/config/security";

const CSRF_COOKIE_NAME = authConfig.csrf.cookieName;
const CSRF_HEADER_NAME = authConfig.csrf.headerName;
const CSRF_SAMESITE = authConfig.csrf.sameSite;
const SESSION_MAX_AGE_MS = authConfig.session.maxAgeMs;

function parseCookieHeader(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.split("=");
    if (!k) continue;
    const key = k.trim();
    const val = rest.join("=").trim();
    if (key) out[key] = decodeURIComponent(val || "");
  }
  return out;
}

export function getCsrfCookieName(): string {
  return CSRF_COOKIE_NAME;
}

export function generateCsrfToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function setCsrfCookie(res: NextResponse, token?: string): string {
  const value = token ?? generateCsrfToken(32);
  res.cookies.set(CSRF_COOKIE_NAME, value, {
    httpOnly: false, // double-submit requires JS-readable cookie
    secure: true,
    sameSite: CSRF_SAMESITE,
    path: "/",
    // align token lifetime to session max-age
    maxAge: Math.floor(SESSION_MAX_AGE_MS / 1000),
    priority: "high",
  });
  return value;
}

/**
 * Returns true if request includes a CSRF cookie.
 */
export function hasCsrfCookie(req: Request): boolean {
  const cookies = parseCookieHeader(req.headers.get("cookie"));
  return typeof cookies[CSRF_COOKIE_NAME] === "string" && cookies[CSRF_COOKIE_NAME].length > 0;
}

/**
 * Verify double-submit CSRF token: header must match cookie exactly.
 * Returns true when valid; false otherwise.
 */
export function verifyCsrf(req: Request): boolean {
  const cookies = parseCookieHeader(req.headers.get("cookie"));
  const cookieVal = cookies[CSRF_COOKIE_NAME];
  const headerVal = req.headers.get(CSRF_HEADER_NAME);

  if (!cookieVal || !headerVal) return false;
  try {
    const a = Buffer.from(cookieVal, "utf8");
    const b = Buffer.from(headerVal, "utf8");
    // Require equal length to prevent subtle leaks
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Ensure request has a CSRF cookie; if missing, set a fresh one on the response.
 * Returns the token value (existing or newly generated).
 */
export function ensureCsrfCookie(req: Request, res: NextResponse): string {
  const cookies = parseCookieHeader(req.headers.get("cookie"));
  const existing = cookies[CSRF_COOKIE_NAME];
  if (existing && existing.length > 0) {
    // refresh cookie attributes without rotating value
    res.cookies.set(CSRF_COOKIE_NAME, existing, {
      httpOnly: false,
      secure: true,
      sameSite: CSRF_SAMESITE,
      path: "/",
      maxAge: Math.floor(SESSION_MAX_AGE_MS / 1000),
      priority: "high",
    });
    return existing;
  }
  return setCsrfCookie(res);
}
// Convenience wrappers for callers expecting these helpers
export function getCsrfTokenFromCookie(req: Request): string | null {
  const cookies = parseCookieHeader(req.headers.get("cookie"));
  const v = cookies[CSRF_COOKIE_NAME];
  return v && v.length > 0 ? v : null;
}

export function requireCsrf(req: Request, res: NextResponse): boolean {
  if (!verifyCsrf(req)) {
    ensureCsrfCookie(req, res);
    return false;
  }
  return true;
}
