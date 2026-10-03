import { handleRpc } from "./mcp";
import type { Env } from "./types";

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
    const responses = (await Promise.all(messages.map((m) => handleRpc(m, env)))).filter(Boolean);

    if (!responses.length) return new Response(null, { status: 202, headers: CORS });

    const body = Array.isArray(payload) ? responses : responses[0];
    return wantsSse ? sse(body) : json(body!);
  },
};
