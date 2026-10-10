import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Env } from "./types";

/**
 * The OAuth login flow, federated to any standard OAuth2/OIDC provider.
 *
 * Clicking "Connect" in a Claude connector lands on /authorize, which shows an
 * approval screen and then forwards to the provider's consent screen. The
 * provider returns to /callback, where the code is exchanged, the account is
 * checked against the pin, and the client's authorization is completed.
 *
 * Everything provider-specific is the four OAUTH_* endpoint/client settings
 * plus how the account is identified (`identify`). The approval screen, the
 * pending-request bookkeeping and the account pin don't know which provider
 * is on the other end.
 */

type OAuthEnv = Env & { OAUTH_PROVIDER: OAuthHelpers; OAUTH_KV: KVNamespace };

/** A request between the approval screen and the provider's callback. */
interface Pending {
  req: AuthRequest;
  /** PKCE verifier, set once the user approves. */
  verifier?: string;
}

const PENDING_PREFIX = "pending-auth:";
const PENDING_TTL = 600;
// __Host- forbids a Domain attribute and requires Secure + Path=/, so no other
// origin can plant this cookie. It binds each step to the browser that started.
const COOKIE = "__Host-wildcard_oauth";

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function page(title: string, body: string, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>${title}</title>
     <body style="font:16px/1.6 system-ui;max-width:34rem;margin:4rem auto;padding:0 1.5rem;color:#14161e">
     <h1 style="font-size:1.4rem">${title}</h1>${body}</body>`,
    {
      status,
      headers: {
        "content-type": "text/html; charset=utf-8",
        // The approval button must not be clickable from inside someone else's frame.
        "x-frame-options": "DENY",
        "content-security-policy": "frame-ancestors 'none'",
        // Each page is one person's step in one sign-in; none should be kept.
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        ...extra,
      },
    },
  );
}

function redirect(location: string, extra: Record<string, string> = {}): Response {
  return new Response(null, { status: 302, headers: { location, ...extra } });
}

const setCookie = (id: string) => `${COOKIE}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${PENDING_TTL}`;
const clearCookie = `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;

function cookieValue(request: Request): string | null {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === COOKIE) return v.join("=");
  }
  return null;
}

function randomId(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Names the first missing setting, or null when the login flow can run. */
function missingConfig(env: Env): string | null {
  for (const name of ["OAUTH_AUTHORIZE_URL", "OAUTH_TOKEN_URL", "OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET"] as const) {
    if (!env[name]) return name;
  }
  // Without a pin, anyone with an account at the provider could log in. Fail
  // closed rather than make "configured" mean "open to the world".
  if (!allowedUsers(env).length) return "OAUTH_ALLOWED_USERS";
  return null;
}

/** Whether an account is on OAUTH_ALLOWED_USERS right now. */
export function isAllowedUser(env: Env, user: string): boolean {
  return allowedUsers(env).includes(user.toLowerCase());
}

function allowedUsers(env: Env): string[] {
  return (env.OAUTH_ALLOWED_USERS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function callbackUrl(request: Request): string {
  return new URL("/callback", request.url).toString();
}

// ------------------------------------------------------- provider-specific

async function authorizeUrl(request: Request, env: Env, state: string, verifier: string): Promise<string> {
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const url = new URL(env.OAUTH_AUTHORIZE_URL!);
  // Anything the provider wants beyond the standard set (Google's
  // access_type, a prompt, an audience) goes in OAUTH_AUTHORIZE_PARAMS.
  for (const [k, v] of new URLSearchParams(env.OAUTH_AUTHORIZE_PARAMS ?? "")) url.searchParams.set(k, v);
  url.searchParams.set("client_id", env.OAUTH_CLIENT_ID!);
  url.searchParams.set("redirect_uri", callbackUrl(request));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", env.OAUTH_SCOPES ?? "openid email");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

interface Tokens {
  access_token?: string;
  id_token?: string;
  error?: string;
}

async function exchangeCode(request: Request, env: Env, code: string, verifier: string): Promise<Tokens | Response> {
  const res = await fetch(env.OAUTH_TOKEN_URL!, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      // GitHub answers form-encoded unless asked for JSON.
      accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: env.OAUTH_CLIENT_ID!,
      client_secret: env.OAUTH_CLIENT_SECRET!,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: callbackUrl(request),
    }),
  });
  const text = await res.text();
  let tokens: Tokens;
  try {
    tokens = JSON.parse(text);
  } catch {
    tokens = Object.fromEntries(new URLSearchParams(text));
  }
  // Some providers report a failed exchange with a 200 and an error field.
  if (!res.ok || tokens.error) {
    return page("Token exchange failed", `<pre>${res.status} ${escapeHtml(text.slice(0, 400))}</pre>`, 502);
  }
  return tokens;
}

/**
 * Who just signed in, as the value of OAUTH_USER_CLAIM (default "email").
 * Read from OAUTH_USERINFO_URL when set (needed for non-OIDC providers such
 * as GitHub), otherwise from the OIDC id_token.
 */
async function identify(env: Env, tokens: Tokens): Promise<string | null> {
  const claim = env.OAUTH_USER_CLAIM || "email";
  let claims: Record<string, unknown> | null = null;

  if (env.OAUTH_USERINFO_URL) {
    if (!tokens.access_token) return null;
    const res = await fetch(env.OAUTH_USERINFO_URL, {
      headers: {
        authorization: `Bearer ${tokens.access_token}`,
        accept: "application/json",
        // GitHub's API rejects requests without one.
        "user-agent": "wildcard-api-mcp",
      },
    });
    if (res.ok) {
      try {
        claims = await res.json();
      } catch {
        // Not JSON (an HTML error page served with 200, say): no one identified.
        return null;
      }
    }
  } else if (tokens.id_token) {
    // The id_token came straight from the token endpoint over TLS, in exchange
    // for our client secret, so its signature need not be checked (OIDC Core
    // 3.1.3.7). The audience still must be us, and must be stated: aud is
    // required by OIDC, so a token without one is not one to trust.
    try {
      const payload = tokens.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      claims = JSON.parse(atob(payload));
    } catch {
      return null;
    }
    const aud = claims?.aud;
    if (!(Array.isArray(aud) ? aud : [aud]).includes(env.OAUTH_CLIENT_ID)) return null;
  }

  if (!claims) return null;
  // An unverified address is just a string someone typed. Some providers send
  // the flag as a string. It must be affirmed outright, from the id_token or
  // from userinfo alike: several providers (Microsoft Entra among them) omit it
  // and let users set `email` freely, so silence is not verification. For a
  // provider that never sends it, such as GitHub, pin a stable id (`login`,
  // `sub`) instead of the email.
  if (claim === "email") {
    if (!(claims && typeof claims === "object")) return null;
    const flag = claims.email_verified;
    if (flag !== true && flag !== "true") return null;
  }
  const value = claims[claim];
  return typeof value === "string" || typeof value === "number" ? String(value) : null;
}

// ------------------------------------------------------- provider-agnostic

async function loadPending(env: OAuthEnv, id: string): Promise<Pending | null> {
  return env.OAUTH_KV.get<Pending>(PENDING_PREFIX + id, "json");
}

export const oauthHandler = {
  async fetch(request: Request, env: OAuthEnv): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/authorize" && request.method === "POST") {
      // The approval form posts back here. The id must match the cookie set
      // when the screen was shown, so a cross-site form can't approve a request
      // the owner never saw: SameSite=Lax keeps the cookie off foreign POSTs.
      const form = await request.formData();
      const id = form.get("id");
      if (typeof id !== "string" || id !== cookieValue(request)) {
        return page("Bad request", "<p>This approval did not come from this browser. Start again from the client.</p>", 400);
      }
      const pending = await loadPending(env, id);
      if (!pending) return page("Expired", "<p>This request expired. Start again from the client.</p>", 400);

      const verifier = randomId();
      await env.OAUTH_KV.put(PENDING_PREFIX + id, JSON.stringify({ ...pending, verifier }), {
        expirationTtl: PENDING_TTL,
      });
      return redirect(await authorizeUrl(request, env, id, verifier));
    }

    if (url.pathname === "/authorize") {
      const missing = missingConfig(env);
      if (missing) return page("Not configured", `<p>${missing} is not set on this Worker.</p>`, 500);
      let req: AuthRequest;
      try {
        req = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      } catch (err) {
        // Usually an unknown client or an unregistered redirect_uri. Never
        // redirect on these: the redirect target may be exactly what failed.
        const reason = err instanceof Error ? err.message : String(err);
        return page("Bad request", `<p>This authorization request is not valid: ${escapeHtml(reason)}</p>`, 400);
      }

      // Registration at /register is open (anyone can register a client), so
      // the client requesting access here may not be one this server's owner
      // recognizes. Show its identity and require a real click before ever
      // reaching the provider — otherwise a registered client with an
      // attacker's redirect_uri could ride the owner's existing login there to
      // collect a token meant for someone else.
      const client = await env.OAUTH_PROVIDER.lookupClient(req.clientId);
      const clientName = client?.clientName?.trim() || req.clientId;

      // The request waits in KV rather than riding in `state`, so nothing the
      // provider echoes back can be forged into a different request.
      const id = randomId();
      await env.OAUTH_KV.put(PENDING_PREFIX + id, JSON.stringify({ req } satisfies Pending), {
        expirationTtl: PENDING_TTL,
      });

      return page(
        "Approve access",
        `<p><b>${escapeHtml(clientName)}</b> is asking to connect to this server.</p>` +
          `<p style="color:#666;font-size:0.9em">It will receive access at: <code>${escapeHtml(req.redirectUri)}</code></p>` +
          `<p style="color:#666;font-size:0.9em">If you don't recognize this, close this tab.</p>` +
          `<form method="POST" action="/authorize">` +
          `<input type="hidden" name="id" value="${escapeHtml(id)}">` +
          `<button type="submit" style="font:inherit;padding:0.6rem 1.4rem;margin-top:1rem;cursor:pointer">Approve</button>` +
          `</form>`,
        200,
        { "set-cookie": setCookie(id) },
      );
    }

    if (url.pathname === "/callback") {
      const error = url.searchParams.get("error");
      if (error) return page("Authorization declined", `<p>The provider returned: ${escapeHtml(error)}</p>`, 400);

      const code = url.searchParams.get("code");
      const id = url.searchParams.get("state");
      if (!code || !id) return page("Bad callback", "<p>Missing code or state.</p>", 400);
      if (id !== cookieValue(request)) {
        return page("Bad callback", "<p>This sign-in was not started from this browser.</p>", 400);
      }

      const pending = await loadPending(env, id);
      if (!pending?.verifier) return page("Expired", "<p>This request expired. Start again from the client.</p>", 400);
      // One use only.
      await env.OAUTH_KV.delete(PENDING_PREFIX + id);

      const tokens = await exchangeCode(request, env, code, pending.verifier);
      if (tokens instanceof Response) return tokens;

      const user = await identify(env, tokens);
      if (!user) {
        return page("Could not identify account", "<p>The provider did not say who signed in. Nothing was changed.</p>", 502);
      }

      // The provider proves who someone is; this decides whether they get in.
      if (!isAllowedUser(env, user)) {
        return page(
          "Wrong account",
          "<p>That is not an account this server is set up for. Nothing was changed.</p>" +
            "<p>Sign in as the right account and connect again.</p>",
          403,
          { "set-cookie": clearCookie },
        );
      }

      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: pending.req,
        userId: user,
        metadata: { label: user },
        scope: pending.req.scope,
        props: { user },
      });
      return redirect(redirectTo, { "set-cookie": clearCookie });
    }

    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          server: "wildcard-api-mcp",
          transport: "streamable-http",
          endpoint: "POST /mcp",
          auth: "OAuth (click Connect), or a PERSONAL_MCP_TOKEN* bearer/path token",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }

    return new Response("Not found", { status: 404 });
  },
};
