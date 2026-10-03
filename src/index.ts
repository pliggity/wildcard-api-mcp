import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { oauthHandler } from "./oauth";
import { mcpHandler, json } from "./mcp-handler";
import { tokenValid } from "./legacy-auth";
import type { Env } from "./types";

/**
 * The legacy shared token, as a Bearer header or a trailing path segment.
 * Kept alongside OAuth so existing clients keep working through the migration.
 */
function legacyToken(request: Request, url: URL): string | null {
  const auth = request.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  const header = request.headers.get("x-mcp-token");
  if (header) return header.trim();
  const match = url.pathname.match(/^\/mcp\/([^/]+)\/?$/);
  return match ? decodeURIComponent(match[1]) : null;
}

const oauthProvider = new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: mcpHandler as any,
  defaultHandler: oauthHandler as any,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const isMcp = url.pathname === "/mcp" || url.pathname.startsWith("/mcp/");

    // A valid legacy token short-circuits OAuth entirely. Anything else on /mcp
    // falls through, so the provider can answer with a 401 that points Claude at
    // the OAuth flow — which is what makes the Connect button appear.
    if (isMcp && tokenValid(legacyToken(request, url), env)) {
      return mcpHandler.fetch(request, env);
    }

    if (url.pathname === "/mcp" && request.method === "OPTIONS") {
      return mcpHandler.fetch(request, env);
    }

    return oauthProvider.fetch(request, env as any, ctx);
  },
} satisfies ExportedHandler<Env>;
