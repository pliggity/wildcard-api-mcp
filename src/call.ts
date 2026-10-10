import { AuthError, resolveAuth } from "./auth";
import { getEffectiveApi, redirectHostAllowed } from "./config";
import { pathMatches } from "./glob";
import type { Env, HttpMethod } from "./types";

const DEFAULT_MAX_CHARS = 30_000;
const HARD_MAX_CHARS = 200_000;
const MAX_PATH_LENGTH = 2_048;
// Anthropic won't accept an image much larger than this, and a base64 blob past
// it just bloats the response for nothing. Over the cap we return a note instead
// of an image the model could never render.
const MAX_IMAGE_BYTES = 5_000_000;
// Generous for a CDN hop or two (Open Library covers take two).
const MAX_REDIRECTS = 5;
// The raster formats an MCP image block can carry to the model. SVG is
// deliberately absent: it is text, and reads fine through the normal path.
const RENDERABLE_IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);

export class CallError extends Error {}

export interface CallInput {
  api: string;
  method?: string;
  path: string;
  query?: Record<string, string | number | boolean | string[]>;
  body?: unknown;
  max_chars?: number;
}

/**
 * A call's outcome. `text` is always present — the status line, plus the body
 * for a text response or a one-line caption for an image. `image` is set only
 * when the upstream returned an image, so the transport can emit an MCP image
 * block instead of mangling binary bytes into text.
 */
export interface CallResult {
  status: number;
  text: string;
  image?: { data: string; mimeType: string };
}

/**
 * base64 without Buffer, which isn't available here (no nodejs_compat). Chunked
 * so a large image can't overflow the argument list String.fromCharCode is
 * handed in one call.
 */
function base64FromBytes(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// The URL parser drops tabs and newlines, reads '\\' as '/', and ends the path
// at '?' or '#'. Any of these lets the path the deny rules see differ from the
// one actually sent, so they are refused outright rather than reasoned about.
const UNSAFE_PATH_CHARS = /[\u0000-\u001f\u007f\\?#]/;

function normalizePath(raw: unknown): string {
  if (typeof raw !== "string") throw new CallError("path must be a string.");
  let path = raw.trim();
  // No real API path is anywhere near this long; bounding it keeps deny-rule
  // matching and URL construction cheap regardless of what the model sends.
  if (path.length > MAX_PATH_LENGTH) {
    throw new CallError(`path may not exceed ${MAX_PATH_LENGTH} characters.`);
  }
  if (UNSAFE_PATH_CHARS.test(path)) {
    throw new CallError(
      "path may not contain control characters, backslashes, '?' or '#'. Pass query parameters in `query`.",
    );
  }
  if (!path.startsWith("/")) path = `/${path}`;
  // A protocol-relative or dot-segment path could otherwise redirect the
  // request to a host the manifests never authorized, or around a deny rule.
  // Checked on the decoded form too, because the URL parser treats '%2e' as
  // '.' when it resolves segments.
  if (path.startsWith("//")) throw new CallError("path may not begin with '//'.");
  const decoded = decodePath(path);
  if (decoded === null) throw new CallError("path contains a malformed percent-escape.");
  if (decoded.split("/").some((seg) => seg === "." || seg === "..")) {
    throw new CallError("path may not contain '.' or '..' segments, encoded or not.");
  }
  return path.replace(/ /g, "%20");
}

function decodePath(path: string): string | null {
  try {
    return decodeURIComponent(path);
  } catch {
    return null;
  }
}

/**
 * Whether a deny rule covers this path. Tested against the path as sent and
 * against the forms an upstream commonly routes it as: percent-decoded
 * ('/%61dmin' and '/admin%2Fusers' reach '/admin/users'), with repeated
 * slashes collapsed, and without a trailing slash. Matching any form errs
 * toward refusing.
 */
function denied(pattern: string, path: string): boolean {
  const decoded = decodePath(path);
  if (decoded === null) return true;
  const forms = new Set([path, decoded]);
  for (const form of [path, decoded]) {
    // Servlet containers drop ';' path parameters before routing, so
    // '/admin;x/users' reaches '/admin/users'.
    for (const variant of [form, form.replace(/;[^/]*/g, "")]) {
      const canonical = variant.replace(/\/{2,}/g, "/");
      forms.add(variant);
      forms.add(canonical);
      if (canonical.length > 1) forms.add(canonical.replace(/\/+$/, ""));
    }
  }
  // Some upstreams (IIS, ASP.NET) route case-insensitively, so '/Admin' must
  // not slip past a rule written as '/admin'.
  const lowerPattern = pattern.toLowerCase();
  for (const form of forms) {
    if (pathMatches(pattern, form) || pathMatches(lowerPattern, form.toLowerCase())) return true;
  }
  return false;
}

/**
 * Masks the API's credential, raw or URL-encoded, in text the upstream wrote
 * (a redirect Location, an error body echoing the request). The model's context
 * is not a safe place for a secret: anything injected into it could repeat the
 * value somewhere else.
 */
function redactor(secrets: string[]): (text: string) => string {
  const needles = new Set<string>();
  for (const s of secrets) {
    // A very short value would match all over ordinary text; anything this
    // short isn't a real credential anyway.
    if (s.length < 8) continue;
    needles.add(s);
    needles.add(encodeURIComponent(s));
    needles.add(new URLSearchParams({ v: s }).toString().slice(2));
  }
  return (text) => {
    for (const n of needles) text = text.split(n).join("[redacted]");
    return text;
  };
}

/** A caller-supplied max_chars, or the default when it isn't a usable number. */
function charLimit(requested: unknown): number {
  const n = typeof requested === "number" && Number.isFinite(requested) && requested > 0 ? Math.floor(requested) : DEFAULT_MAX_CHARS;
  return Math.min(n, HARD_MAX_CHARS);
}

/**
 * Reads at most `maxBytes` of a body, then cancels the rest. A Worker has a
 * fixed memory budget, and an upstream (or anything it proxies) choosing to
 * stream gigabytes must not be able to spend it. `complete` is false when the
 * body was cut short.
 */
async function readCapped(res: Response, maxBytes: number): Promise<{ bytes: Uint8Array; complete: boolean }> {
  if (!res.body) return { bytes: new Uint8Array(0), complete: true };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let complete = true;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
    if (total > maxBytes) {
      complete = false;
      await reader.cancel().catch(() => {});
      break;
    }
  }
  const bytes = new Uint8Array(Math.min(total, maxBytes));
  let offset = 0;
  for (const chunk of chunks) {
    const take = Math.min(chunk.byteLength, bytes.length - offset);
    bytes.set(chunk.subarray(0, take), offset);
    offset += take;
    if (offset >= bytes.length) break;
  }
  return { bytes, complete };
}

function declaredLength(res: Response): number | null {
  const n = Number(res.headers.get("content-length"));
  return Number.isFinite(n) && n >= 0 && res.headers.has("content-length") ? n : null;
}

function buildQuery(
  query: CallInput["query"],
  defaults: Record<string, string> = {},
  credential: Record<string, string> = {},
): string {
  const merged = { ...defaults, ...(query && typeof query === "object" ? query : {}) };
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(merged)) {
    // Repeated params are expressed as repeated keys.
    if (Array.isArray(value)) value.forEach((v) => params.append(key, String(v)));
    else params.append(key, String(value));
  }
  // Set last, with set(), so a caller passing the same key can neither replace
  // the credential nor send a second copy alongside it.
  for (const [key, value] of Object.entries(credential)) params.set(key, value);
  const s = params.toString();
  return s ? `?${s}` : "";
}

export async function callApi(input: CallInput, env: Env): Promise<CallResult> {
  // Resolved through the overlay, not the bundle: a disabled API must be
  // unreachable, not merely absent from the listing.
  const api = await getEffectiveApi(env, input.api);
  if (!api) throw new CallError(`Unknown api '${input.api}'. Call list_apis to see what is available.`);

  const method = (input.method ?? "GET").toUpperCase() as HttpMethod;
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    throw new CallError(`Unsupported method '${method}'.`);
  }
  if (method !== "GET" && !api.write) {
    throw new CallError(`'${api.id}' is read-only on this server; only GET is permitted.`);
  }

  const path = normalizePath(input.path);

  for (const rule of api.deny ?? []) {
    if ((rule.method === "*" || rule.method === method) && denied(rule.path, path)) {
      throw new CallError(`Refused: ${method} ${path} is blocked for '${api.id}'. ${rule.reason}`);
    }
  }

  const auth = await resolveAuth(api, env);
  const base = auth.baseUrl ?? api.baseUrl;
  const baseUrl = new URL(base);
  const basePath = baseUrl.pathname.replace(/\/$/, "");
  const url = new URL(`${base}${path}${buildQuery(input.query, api.defaultQuery, auth.query)}`);
  // What the model is shown: the same request with no credential in it. Built
  // separately rather than masked afterwards, so nothing returned below is
  // derived from a URL that ever held the secret.
  const shown = new URL(`${base}${path}${buildQuery(input.query, api.defaultQuery)}`);

  // Belt and braces: the manifest's host is the only one this call may reach,
  // and only beneath its base path — '/v1' must not admit '/v1beta'.
  if (url.host !== baseUrl.host || (url.pathname !== basePath && !url.pathname.startsWith(`${basePath}/`))) {
    throw new CallError(`Refused: the resulting URL escapes the base URL for '${api.id}'.`);
  }
  // And the deny rules again, on the path the parser actually produced, so
  // nothing it normalized can differ from what was checked above.
  const sentPath = url.pathname.slice(basePath.length) || "/";
  for (const rule of api.deny ?? []) {
    if ((rule.method === "*" || rule.method === method) && denied(rule.path, sentPath)) {
      throw new CallError(`Refused: ${method} ${sentPath} is blocked for '${api.id}'. ${rule.reason}`);
    }
  }

  // json stays preferred, but an endpoint that only speaks images must not be
  // sent an Accept that excludes them — some upstreams answer 406 to that. The
  // wildcard keeps json first while letting an image (or anything else) through.
  const headers: Record<string, string> = { ...auth.headers, accept: "application/json, */*" };
  let payload: string | undefined;
  if (input.body !== undefined && method !== "GET") {
    payload = typeof input.body === "string" ? input.body : JSON.stringify(input.body);
    headers["content-type"] = "application/json";
  }

  // Redirects are never followed by fetch itself. Following one blindly would
  // let an open redirect on an allowed host send this request (and, depending
  // on the runtime, its credential) to a host no manifest names. A GET may be
  // followed by hand, but only over https to a host on ALLOWED_REDIRECT_HOSTS,
  // and those hops carry no credential.
  let res = await fetch(url.toString(), { method, headers, body: payload, redirect: "manual" });
  // Only the upstream's own words (a Location, a body) can still carry the
  // credential, if the API echoes it; those are masked before they're returned.
  const secret = typeof api.auth === "object" ? env[api.auth.secret] : undefined;
  const redact = redactor(typeof secret === "string" ? [secret] : []);
  let at = url;
  const hops: string[] = [];
  while (res.status >= 300 && res.status < 400) {
    const location = res.headers.get("location");
    let next: URL | null = null;
    try {
      next = location ? new URL(location, at) : null;
    } catch {
      next = null;
    }
    const why =
      !next ? "it gave no usable location"
      : method !== "GET" ? "only GET redirects are followed"
      : next.protocol !== "https:" ? "it is not https"
      : !redirectHostAllowed(env, next.host) ? `${next.host} is not on ALLOWED_REDIRECT_HOSTS`
      : hops.length >= MAX_REDIRECTS ? `it exceeded ${MAX_REDIRECTS} redirects`
      : null;
    await res.body?.cancel().catch(() => {});
    if (why || !next) {
      return {
        status: res.status,
        text: redact(
          `${res.status} ${res.statusText} · ${method} ${shown.pathname}${shown.search}\n\n` +
            `[redirected${location ? ` to ${location}` : ""} — not followed because ${why}. ` +
            "If the new location is under the same API, call that path instead.]",
        ),
      };
    }
    hops.push(next.host);
    at = next;
    res = await fetch(next.toString(), { method: "GET", headers: { accept: headers.accept }, redirect: "manual" });
  }
  const contentType = res.headers.get("content-type") ?? "unknown";
  const via = hops.length ? ` · via ${hops.join(" → ")}` : "";
  const head = redact(`${res.status} ${res.statusText} · ${method} ${shown.pathname}${shown.search}${via} · ${contentType}`);
  const mimeType = contentType.split(";")[0].trim().toLowerCase();

  // Images must never go through res.text(): decoding binary bytes as UTF-8
  // replaces every byte that isn't valid UTF-8 with U+FFFD, corrupting the image
  // beyond recovery before it ever leaves the Worker. Read the raw bytes and
  // return them as a base64 image block the model can actually see.
  if (mimeType.startsWith("image/") && mimeType !== "image/svg+xml") {
    if (!res.ok) {
      // An error carrying an image content-type is not a real image — show the
      // status rather than a body that won't render.
      await res.body?.cancel().catch(() => {});
      return { status: res.status, text: `${head}\n\n[the API rejected this call; no image returned]` };
    }
    if (!RENDERABLE_IMAGE_TYPES.has(mimeType)) {
      await res.body?.cancel().catch(() => {});
      return {
        status: res.status,
        text:
          `${head}\n\n[${mimeType} image not shown — only png, jpeg, gif and webp ` +
          "can be displayed; request one of those if the API supports it]",
      };
    }
    // Checked before reading where the size is declared, and enforced while
    // reading where it isn't, so an oversized image is never held in full.
    const declared = declaredLength(res);
    const { bytes, complete } =
      declared !== null && declared > MAX_IMAGE_BYTES
        ? (await res.body?.cancel().catch(() => {}), { bytes: new Uint8Array(0), complete: false })
        : await readCapped(res, MAX_IMAGE_BYTES);
    if (!complete) {
      return {
        status: res.status,
        text:
          `${head}\n\n[image is ${declared ?? `more than ${MAX_IMAGE_BYTES}`} bytes, over the ${MAX_IMAGE_BYTES}-byte cap and cannot be ` +
          "displayed — request a smaller size if the API supports it]",
      };
    }
    return {
      status: res.status,
      text: `${head}\n\n[${bytes.byteLength}-byte ${mimeType} image returned below]`,
      image: { data: base64FromBytes(bytes), mimeType },
    };
  }

  const limit = charLimit(input.max_chars);
  // A UTF-8 character is at most 4 bytes, so this many bytes always holds
  // `limit` characters; nothing past it is ever read.
  const { bytes, complete } = await readCapped(res, limit * 4);
  const raw = new TextDecoder().decode(bytes);
  let text = raw;
  let truncated = !complete;
  if (text.length > limit) {
    text = text.slice(0, limit);
    truncated = true;
  }

  const total = complete ? `${raw.length}` : `more than ${limit}`;
  const tail = truncated
    ? `\n\n[truncated at ${limit} of ${total} chars — narrow the request with query params or a fields selector, or raise max_chars]`
    : "";
  const hint = !res.ok ? "\n\n[the API rejected this call; the body above is its error]" : "";

  return { status: res.status, text: `${head}\n\n${redact(text) || "(empty body)"}${tail}${hint}` };
}

export function describeError(err: unknown): string {
  if (err instanceof AuthError) return `Auth error: ${err.message}`;
  if (err instanceof CallError) return err.message;
  return `Request failed: ${err instanceof Error ? err.message : String(err)}`;
}
