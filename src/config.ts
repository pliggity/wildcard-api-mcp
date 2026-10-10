import { APIS } from "./registry";
import type { ApiManifest, Env } from "./types";
import { validateManifests } from "./validate";

/**
 * Runtime overlay on top of the manifests baked into the bundle.
 *
 * apis.json is a build-time import, so nothing in it can change without a
 * deploy. This adds the runtime adjustments worth having — switching an API
 * off, or registering a new one — without moving hosts, credentials or deny
 * rules out of code, where a deploy is still the only thing that can alter
 * them.
 *
 * A disabled API is gone from the server's surface, not merely hidden: it
 * leaves list_apis, describe_api stops resolving it, call_api refuses it, and
 * check_auth skips it. Since call_api resolves through here, its host is no
 * longer reachable either. That is as close to removal as a bundled manifest
 * can get, and unlike a real deletion it is reversible from the same tool.
 */

const OVERLAY_KEY = "config:overlay";

export interface ConfigOverlay {
  /** API ids switched off. Ids that no longer exist are ignored on read. */
  disabled: string[];
  /**
   * Manifests added at runtime, so a new API needs no deploy. These are the
   * reason validateAddition exists: a bundled manifest was reviewed on the way
   * into the repo, and one of these was not.
   */
  added: ApiManifest[];
  /**
   * Why the stored overlay could not be read, when it could not be.
   *
   * This is the honest half of failing soft. Falling back to the bundled
   * manifests keeps the server answering, but it also means anything switched
   * off quietly comes back — so the fallback has to be visible. get_config and
   * check_auth both report it rather than showing every API as enabled and
   * leaving you to wonder why a disabled one is answering.
   */
  degraded?: string;
}

const EMPTY: ConfigOverlay = { disabled: [], added: [] };

/**
 * Fail-soft by design: a malformed or unreadable overlay falls back to the
 * bundled manifests rather than throwing. The overlay is a convenience, and a
 * bad KV value must never be able to take the whole server down — which is
 * exactly what would happen if this threw on a cold isolate.
 */
export async function readOverlay(env: Env): Promise<ConfigOverlay> {
  if (!env.OAUTH_KV) return { disabled: [], added: [], degraded: "no KV namespace is bound" };
  let raw: string | null;
  try {
    raw = await env.OAUTH_KV.get(OVERLAY_KEY);
  } catch (err) {
    return { disabled: [], added: [], degraded: `storage read failed — ${err instanceof Error ? err.message : String(err)}` };
  }
  // No key yet is the ordinary empty state, not a failure.
  if (!raw) return EMPTY;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.disabled)) {
      return { disabled: [], added: [], degraded: "stored config is malformed (no 'disabled' array)" };
    }
    // Stored manifests are re-validated on every read, never trusted because
    // they were valid when written: the rules can tighten between deploys, and
    // this is the only gate between KV and a live outbound request.
    let added: ApiManifest[] = [];
    if (Array.isArray(parsed.added) && parsed.added.length) {
      try {
        added = validateManifests(parsed.added);
      } catch (err) {
        return {
          disabled: [],
          added: [],
          degraded: `a stored API manifest no longer validates — ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }
    return { disabled: parsed.disabled.filter((id: unknown): id is string => typeof id === "string"), added };
  } catch {
    return { disabled: [], added: [], degraded: "stored config is not valid JSON" };
  }
}

export async function writeOverlay(env: Env, overlay: ConfigOverlay): Promise<void> {
  if (!env.OAUTH_KV) {
    throw new Error("No KV namespace is bound, so configuration cannot be saved.");
  }
  // `degraded` is a read-time diagnostic, never stored.
  await env.OAUTH_KV.put(OVERLAY_KEY, JSON.stringify({ disabled: overlay.disabled, added: overlay.added }));
}

/** Apply an already-read overlay, so a caller that needs both costs one KV read. */
export function applyOverlay(overlay: ConfigOverlay): ApiManifest[] {
  const all = overlay.added.length ? [...APIS, ...overlay.added] : APIS;
  if (!overlay.disabled.length) return all;
  return all.filter((a) => !overlay.disabled.includes(a.id));
}

/** True for a manifest that came from KV rather than the bundle. */
export function isAdded(overlay: ConfigOverlay, id: string): boolean {
  return overlay.added.some((a) => a.id === id);
}

/** The manifests this server will actually act on right now. */
export async function effectiveApis(env: Env): Promise<ApiManifest[]> {
  return applyOverlay(await readOverlay(env));
}

export async function getEffectiveApi(env: Env, id: string): Promise<ApiManifest | undefined> {
  return (await effectiveApis(env)).find((a) => a.id === id);
}

/** Every id this server knows, enabled or not, bundled or added. */
export function knownIds(overlay: ConfigOverlay): string[] {
  return [...APIS.map((a) => a.id), ...overlay.added.map((a) => a.id)];
}

/** Hosts a runtime-added API may point at, from a Worker secret. */
export function allowedNewHosts(env: Env): string[] {
  const raw = typeof env.ALLOWED_NEW_HOSTS === "string" ? env.ALLOWED_NEW_HOSTS : "";
  return raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Hosts call_api may follow a redirect to, from the ALLOWED_REDIRECT_HOSTS var
 * in wrangler.jsonc. An entry is an exact hostname, or `*.example.org` for any
 * subdomain of it (not example.org itself). Like ALLOWED_NEW_HOSTS it changes
 * only from a terminal, so nothing holding the OAuth grant can widen it.
 */
export function allowedRedirectHosts(env: Env): string[] {
  const raw = typeof env.ALLOWED_REDIRECT_HOSTS === "string" ? env.ALLOWED_REDIRECT_HOSTS : "";
  return raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

export function redirectHostAllowed(env: Env, host: string): boolean {
  const h = host.toLowerCase();
  return allowedRedirectHosts(env).some((entry) =>
    entry.startsWith("*.") ? h.endsWith(entry.slice(1)) && h.length > entry.length - 1 : h === entry,
  );
}

/** Secret names a runtime-added API may read. */
const ADDED_SECRET_PATTERN = /^API_[A-Z0-9_]+$/;
/** How a declarative credential is attached to a request, for comparing two manifests. */
function sendsAs(auth: Exclude<ApiManifest["auth"], string>): string {
  switch (auth.type) {
    case "header":
      return `header ${auth.header.toLowerCase()}${auth.prefix ? ` (prefix ${JSON.stringify(auth.prefix)})` : ""}`;
    case "query":
      return `query param ${auth.param}`;
    default:
      return auth.type;
  }
}

/**
 * Bounds on what add_api will store. Generous for a real API description, but
 * every added manifest is re-read and re-validated on each request, and shown
 * to the model by describe_api, so neither may grow without limit.
 */
const MAX_ADDED_APIS = 50;
const MAX_ADDED_MANIFEST_BYTES = 128_000;

/**
 * The gate on everything a caller can register at runtime.
 *
 * Four rules, each closing a way an added manifest could otherwise reach
 * further than intended:
 *
 *  - the host must be on a list that only changes from a terminal, so nothing
 *    that merely holds a client's grant can point this server somewhere new;
 *  - https only, since a credential is attached to every request;
 *  - any bespoke, code-backed auth flow (one that isn't a plain declarative
 *    bearer/header/query/basic type) is refused for a runtime addition,
 *    because selecting one would attach an existing credential to a host it
 *    was never issued for;
 *  - a credential may only be read from a secret named API_*, so a manifest
 *    cannot name an unrelated secret and have it sent out as a bearer token;
 *  - and not one another manifest already sends to a different host, so an
 *    allowed host can't be handed the credential issued for another.
 */
export function validateAddition(env: Env, candidate: unknown, overlay: ConfigOverlay): ApiManifest {
  if (overlay.added.length >= MAX_ADDED_APIS) {
    throw new Error(`At most ${MAX_ADDED_APIS} APIs can be added at runtime. Remove one, or move some into apis.json.`);
  }
  const size = JSON.stringify(candidate ?? null).length;
  if (size > MAX_ADDED_MANIFEST_BYTES) {
    throw new Error(
      `The manifest is ${size} bytes; runtime additions are capped at ${MAX_ADDED_MANIFEST_BYTES}. ` +
        "Trim it to the endpoints you need, or add it to apis.json and deploy.",
    );
  }

  // Validated alongside everything else so duplicate ids are caught here too.
  const merged = validateManifests([...APIS, ...overlay.added, candidate]);
  const api = merged[merged.length - 1];

  const url = new URL(api.baseUrl);
  if (url.protocol !== "https:") {
    throw new Error(`baseUrl must be https — '${api.baseUrl}' is not.`);
  }

  const allowed = allowedNewHosts(env);
  if (!allowed.length) {
    throw new Error(
      "No hosts are allowed for runtime-added APIs. Set them first with " +
        "`npm run secret -- put ALLOWED_NEW_HOSTS` (comma-separated hostnames).",
    );
  }
  if (!allowed.includes(url.host.toLowerCase())) {
    throw new Error(
      `Host '${url.host}' is not allowed. Allowed: ${allowed.join(", ")}. ` +
        "Add it with `npm run secret -- put ALLOWED_NEW_HOSTS`.",
    );
  }

  if (typeof api.auth === "string" && api.auth !== "none") {
    throw new Error(
      `auth '${api.auth}' is a built-in flow reserved for bundled APIs; it would attach an existing ` +
        "credential to this host. Use a declarative type (bearer, header, query, basic) or 'none'.",
    );
  }
  if (typeof api.auth === "object" && !ADDED_SECRET_PATTERN.test(api.auth.secret)) {
    throw new Error(
      `auth.secret must be named API_* for a runtime-added API (got '${api.auth.secret}'), so it cannot ` +
        "read a secret belonging to something else.",
    );
  }
  if (typeof api.auth === "object") {
    const auth = api.auth;
    const secret = auth.secret;
    for (const other of [...APIS, ...overlay.added]) {
      if (typeof other.auth !== "object" || other.auth.secret !== secret) continue;
      if (new URL(other.baseUrl).host.toLowerCase() !== url.host.toLowerCase()) {
        throw new Error(
          `auth.secret ${secret} is already sent to ${new URL(other.baseUrl).host} by '${other.id}'. A credential ` +
            "goes only to the host it was issued for; name a new API_* secret for this one.",
        );
      }
      // Same host, but the credential must also travel the same way: moving a
      // header secret into a query param, or into another header, changes where
      // it ends up (URLs get logged and echoed back) without the owner's say.
      if (sendsAs(other.auth) !== sendsAs(auth)) {
        throw new Error(
          `auth.secret ${secret} is already sent as ${sendsAs(other.auth)} by '${other.id}'. Reusing it must keep ` +
            "that exact auth (same type, header or param); otherwise name a new API_* secret.",
        );
      }
    }
  }

  return api;
}
