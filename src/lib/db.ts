// src/lib/db.ts
import { PrismaClient } from '../generated/prisma';

declare global {
  var __prisma: PrismaClient | undefined;
}

export const prisma: PrismaClient =
  globalThis.__prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['error', 'warn']
        : ['error'],
  });

if (process.env.NODE_ENV !== 'production') {
  globalThis.__prisma = prisma;
}

export const nowMs = () => Date.now();

export const toBigIntMs = (ms: number): bigint => BigInt(ms);
export const fromBigIntMs = (ms?: bigint | null): number | null =>
  typeof ms === 'bigint' ? Number(ms) : null;

export default prisma;
