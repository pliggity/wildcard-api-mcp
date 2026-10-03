import { AuthError, resolveAuth } from "./auth";
import { getEffectiveApi } from "./config";
import { pathMatches } from "./glob";
import type { Env, HttpMethod } from "./types";

const DEFAULT_MAX_CHARS = 30_000;
const HARD_MAX_CHARS = 200_000;
const MAX_PATH_LENGTH = 2_048;
// Anthropic won't accept an image much larger than this, and a base64 blob past
// it just bloats the response for nothing. Over the cap we return a note instead
// of an image the model could never render.
const MAX_IMAGE_BYTES = 5_000_000;
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
function base64FromBytes(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function normalizePath(raw: string): string {
  let path = raw.trim();
  // No real API path is anywhere near this long; bounding it keeps deny-rule
  // matching and URL construction cheap regardless of what the model sends.
  if (path.length > MAX_PATH_LENGTH) {
    throw new CallError(`path may not exceed ${MAX_PATH_LENGTH} characters.`);
  }
  if (!path.startsWith("/")) path = `/${path}`;
  // A protocol-relative or dot-segment path could otherwise redirect the
  // request to a host the manifests never authorized.
  if (path.startsWith("//")) throw new CallError("path may not begin with '//'.");
  if (path.split("/").includes("..")) throw new CallError("path may not contain '..' segments.");
  return path.replace(/ /g, "%20");
}

function buildQuery(
  query: CallInput["query"],
  defaults: Record<string, string> = {},
): string {
  const merged = { ...defaults, ...(query ?? {}) };
  if (!Object.keys(merged).length) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(merged)) {
    // Repeated params are expressed as repeated keys.
    if (Array.isArray(value)) value.forEach((v) => params.append(key, String(v)));
    else params.append(key, String(value));
  }
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
    if ((rule.method === "*" || rule.method === method) && pathMatches(rule.path, path)) {
      throw new CallError(`Refused: ${method} ${path} is blocked for '${api.id}'. ${rule.reason}`);
    }
  }

  const auth = await resolveAuth(api, env);
  const base = auth.baseUrl ?? api.baseUrl;
  const baseUrl = new URL(base);
  const url = new URL(
    `${base}${path}${buildQuery(input.query, { ...auth.query, ...api.defaultQuery })}`,
  );

  // Belt and braces: the manifest's host is the only one this call may reach.
  if (url.host !== baseUrl.host || !url.pathname.startsWith(baseUrl.pathname.replace(/\/$/, ""))) {
    throw new CallError(`Refused: the resulting URL escapes the base URL for '${api.id}'.`);
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

  const res = await fetch(url.toString(), { method, headers, body: payload });
  const contentType = res.headers.get("content-type") ?? "unknown";
  const head = `${res.status} ${res.statusText} · ${method} ${url.pathname}${url.search} · ${contentType}`;
  const mimeType = contentType.split(";")[0].trim().toLowerCase();

  // Images must never go through res.text(): decoding binary bytes as UTF-8
  // replaces every byte that isn't valid UTF-8 with U+FFFD, corrupting the image
  // beyond recovery before it ever leaves the Worker. Read the raw bytes and
  // return them as a base64 image block the model can actually see.
  if (mimeType.startsWith("image/") && mimeType !== "image/svg+xml") {
    if (!res.ok) {
      // An error carrying an image content-type is not a real image — show the
      // status rather than a body that won't render.
      return { status: res.status, text: `${head}\n\n[the API rejected this call; no image returned]` };
    }
    const buf = await res.arrayBuffer();
    if (!RENDERABLE_IMAGE_TYPES.has(mimeType)) {
      return {
        status: res.status,
        text:
          `${head}\n\n[${buf.byteLength}-byte ${mimeType} image not shown — only png, jpeg, gif and webp ` +
          "can be displayed; request one of those if the API supports it]",
      };
    }
    if (buf.byteLength > MAX_IMAGE_BYTES) {
      return {
        status: res.status,
        text:
          `${head}\n\n[image is ${buf.byteLength} bytes, over the ${MAX_IMAGE_BYTES}-byte cap and cannot be ` +
          "displayed — request a smaller size if the API supports it]",
      };
    }
    return {
      status: res.status,
      text: `${head}\n\n[${buf.byteLength}-byte ${mimeType} image returned below]`,
      image: { data: base64FromBytes(buf), mimeType },
    };
  }

  const raw = await res.text();

  const limit = Math.min(input.max_chars ?? DEFAULT_MAX_CHARS, HARD_MAX_CHARS);
  let text = raw;
  let truncated = false;
  if (text.length > limit) {
    text = text.slice(0, limit);
    truncated = true;
  }

  const tail = truncated
    ? `\n\n[truncated at ${limit} of ${raw.length} chars — narrow the request with query params or a fields selector, or raise max_chars]`
    : "";
  const hint = !res.ok ? "\n\n[the API rejected this call; the body above is its error]" : "";

  return { status: res.status, text: `${head}\n\n${text || "(empty body)"}${tail}${hint}` };
}

export function describeError(err: unknown): string {
  if (err instanceof AuthError) return `Auth error: ${err.message}`;
  if (err instanceof CallError) return err.message;
  return `Request failed: ${err instanceof Error ? err.message : String(err)}`;
}
