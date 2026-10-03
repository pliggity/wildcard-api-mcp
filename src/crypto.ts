import type { Env } from "./types";

/**
 * Envelope encryption for credentials stored in KV.
 *
 * KV differs from a Worker secret in that its values can be read back — by the
 * dashboard, by `wrangler kv key get`, or by any API token scoped to the
 * namespace. Storing an OAuth refresh token there in the clear would mean a
 * read-only KV token is enough to take full access to the upstream account, with
 * none of this server's deny rules applying. Encrypting with a key held as a
 * Worker secret restores the property that reading KV alone gets you nothing.
 *
 * This does not defend against a compromised Cloudflare account — anyone who
 * can deploy code can read the secret too. It closes the narrower gap.
 */

const PREFIX = "v1:";

async function key(env: Env): Promise<CryptoKey> {
  const b64 = env.KV_ENCRYPTION_KEY;
  if (!b64) {
    throw new Error(
      "KV_ENCRYPTION_KEY is not set, so credentials cannot be stored safely. " +
        "Generate one with `npm run gen-token` and set it with `npm run secret -- put KV_ENCRYPTION_KEY`.",
    );
  }
  const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error("KV_ENCRYPTION_KEY must be 32 bytes, base64-encoded.");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

export async function encrypt(env: Env, plaintext: string): Promise<string> {
  // A fresh IV per write; reusing one under the same key breaks AES-GCM.
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(env), new TextEncoder().encode(plaintext)),
  );
  const joined = new Uint8Array(iv.length + ct.length);
  joined.set(iv);
  joined.set(ct, iv.length);
  return PREFIX + b64(joined);
}

/** Values written before encryption existed are returned as-is. */
export function isEncrypted(stored: string): boolean {
  return stored.startsWith(PREFIX);
}

export async function decrypt(env: Env, stored: string): Promise<string> {
  if (!isEncrypted(stored)) return stored;
  const joined = Uint8Array.from(atob(stored.slice(PREFIX.length)), (c) => c.charCodeAt(0));
  const iv = joined.slice(0, 12);
  const ct = joined.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await key(env), ct);
  return new TextDecoder().decode(plain);
}
