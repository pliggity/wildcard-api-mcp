import type { Env } from "./types";

/** Constant-time compare so a token can't be recovered by timing the gate. */
export function secretEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Every secret named PERSONAL_MCP_TOKEN* is a valid shared credential. */
export function acceptedTokens(env: Env): string[] {
  return Object.entries(env)
    .filter(([k, v]) => k.startsWith("PERSONAL_MCP_TOKEN") && typeof v === "string" && v)
    .map(([, v]) => v as string);
}

export function tokenValid(token: string | null, env: Env): boolean {
  if (!token) return false;
  const accepted = acceptedTokens(env);
  if (!accepted.length) return false;
  // Compare against all candidates regardless of an early match, so response
  // time doesn't reveal which token was presented.
  return accepted.reduce((found, c) => secretEquals(token, c) || found, false);
}
