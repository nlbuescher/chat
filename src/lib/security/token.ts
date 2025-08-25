// src/lib/security/token.ts
import { randomBytes, createHash } from 'node:crypto';
import { authConfig } from '@/lib/config/security';

export const RESET_TOKEN_TTL_MS = authConfig.tokens.resetTtlMs;

export function generateToken(bytes = 32): { token: string; hash: string } {
  const token = randomBytes(bytes).toString('base64url'); // URL-safe
  const hash = hashToken(token);
  return { token, hash };
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('base64url');
}
