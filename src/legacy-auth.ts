import type { Env } from "./types";

/**
 * Shorter than this, a shared token is guessable rather than secret, so it is
 * ignored as if unset. `npm run gen-token` produces 32 characters.
 */
export const MIN_TOKEN_LENGTH = 16;

async function digest(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

/**
 * Constant-time compare so a token can't be recovered by timing the gate.
 * Both sides are hashed first, so the comparison is always 32 bytes and the
 * time taken doesn't reveal the real token's length either.
 */
export async function secretEquals(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/** Every secret named PERSONAL_MCP_TOKEN* that is long enough to be one. */
export function acceptedTokens(env: Env): string[] {
  return Object.entries(env)
    .filter(([k, v]) => k.startsWith("PERSONAL_MCP_TOKEN") && typeof v === "string" && v.length >= MIN_TOKEN_LENGTH)
    .map(([, v]) => v as string);
}

export async function tokenValid(token: string | null, env: Env): Promise<boolean> {
  if (!token) return false;
  const accepted = acceptedTokens(env);
  if (!accepted.length) return false;
  // Compare against all candidates regardless of an early match, so response
  // time doesn't reveal which token was presented.
  const matches = await Promise.all(accepted.map((c) => secretEquals(token, c)));
  return matches.includes(true);
}
