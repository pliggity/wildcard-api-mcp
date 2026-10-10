import { handleRpc } from "./mcp";
import { isAllowedUser } from "./oauth";
import type { Env } from "./types";

/**
 * MCP (2025-06-18) dropped JSON-RPC batching; it is still accepted for older
 * clients, but bounded, since every message in a batch can be an outbound call.
 */
const MAX_BATCH = 20;

export const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  "access-control-allow-headers":
    "content-type, authorization, x-mcp-token, mcp-session-id, mcp-protocol-version",
  "access-control-expose-headers": "mcp-session-id",
};

export function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS, ...extra },
  });
}

/** A single JSON-RPC response framed as one SSE event, then the stream ends. */
function sse(body: unknown): Response {
  return new Response(`event: message\ndata: ${JSON.stringify(body)}\n\n`, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache", ...CORS },
  });
}

/**
 * Serves MCP over streamable HTTP. Authentication happens before this runs —
 * either the legacy shared token in src/index.ts, or the OAuth provider.
 */
export const mcpHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    // This server never sends server-initiated messages, so decline the GET
    // stream per the spec rather than leaving the client hanging on it.
    if (request.method === "GET") return new Response("Method Not Allowed", { status: 405, headers: CORS });
    if (request.method === "DELETE") return new Response(null, { status: 204, headers: CORS });
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: CORS });

    let payload: any;
    try {
      payload = await request.json();
    } catch {
      return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
    }

    const accept = request.headers.get("accept") ?? "";
    const wantsSse = accept.includes("text/event-stream") && !accept.includes("application/json");

    const messages = Array.isArray(payload) ? payload : [payload];
    if (!messages.length || messages.length > MAX_BATCH) {
      return json(
        { jsonrpc: "2.0", id: null, error: { code: -32600, message: `A batch must hold 1 to ${MAX_BATCH} messages.` } },
        400,
      );
    }
    const responses = (
      await Promise.all(
        messages.map((m) =>
          m && typeof m === "object" && !Array.isArray(m) && typeof m.method === "string"
            ? handleRpc(m, env)
            : { jsonrpc: "2.0", id: m?.id ?? null, error: { code: -32600, message: "Invalid Request" } },
        ),
      )
    ).filter(Boolean);

    if (!responses.length) return new Response(null, { status: 202, headers: CORS });

    const body = Array.isArray(payload) ? responses : responses[0];
    return wantsSse ? sse(body) : json(body!);
  },
};

/**
 * The OAuth provider's view of /mcp. A grant carries the account it was issued
 * to, and that account is checked against OAUTH_ALLOWED_USERS on every
 * request, not just at login: removing someone from the list cuts off the
 * tokens and refresh tokens they already hold, rather than leaving them
 * working until they lapse.
 */
export const oauthMcpHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext & { props?: { user?: unknown } }): Promise<Response> {
    const user = ctx?.props?.user;
    if (typeof user !== "string" || !isAllowedUser(env, user)) {
      return json({ error: "forbidden", error_description: "This account is no longer allowed on this server." }, 403);
    }
    return mcpHandler.fetch(request, env);
  },
};
