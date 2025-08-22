// src/lib/security/hash.ts
import argon2 from 'argon2';

export const ARGON2_OPTS: argon2.Options & { type: number } = {
  type: argon2.argon2id,
  memoryCost: 64 * 1024, // 64 MiB
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
};

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTS);
}

export async function verifyPassword(
  password: string,
  passwordHash: string
): Promise<{ valid: boolean; needsRehash: boolean }> {
  try {
    const valid = await argon2.verify(passwordHash, password, ARGON2_OPTS);
    let needsRehash = false;

    // node-argon2 exposes needsRehash in newer versions; feature-detect.
    const anyArgon = argon2 as unknown as {
      needsRehash?: (hash: string, opts: typeof ARGON2_OPTS) => boolean;
    };
    if (valid && typeof anyArgon.needsRehash === 'function') {
      needsRehash = anyArgon.needsRehash(passwordHash, ARGON2_OPTS);
    }

    return { valid, needsRehash };
  } catch {
    return { valid: false, needsRehash: false };
  }
}

export function argon2ParamsSummary(): string {
  return `argon2id m=${ARGON2_OPTS.memoryCost} t=${ARGON2_OPTS.timeCost} p=${ARGON2_OPTS.parallelism} len=${ARGON2_OPTS.hashLength}`;
}
