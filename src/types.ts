export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Endpoint {
  method: HttpMethod;
  path: string;
  summary: string;
  /** Query parameter names the endpoint understands. */
  query?: string[];
  /** One-line shape hint for the JSON request body. */
  body?: string;
  /** Anything the caller needs to know that the signature doesn't convey. */
  notes?: string;
}

/** A method + path-glob pair that is refused even when the API allows writes. */
export interface DenyRule {
  method: HttpMethod | "*";
  path: string;
  reason: string;
}

/**
 * How a manifest's credential is applied. The object forms cover the ordinary
 * cases — a value in a Worker secret, applied to each request — so most new
 * APIs need no code at all, just a manifest and a secret. A credential they
 * can't express (per-user delegated OAuth, a signature scheme) is added as a
 * new string literal here, handled in src/auth.ts.
 */
export type AuthProvider =
  | "none"
  /** Authorization: Bearer <secret> */
  | { type: "bearer"; secret: string }
  /** A named header, e.g. { header: "x-api-key" }. `prefix` prepends to the value. */
  | { type: "header"; secret: string; header: string; prefix?: string }
  /** A query parameter, e.g. { param: "apikey" }. */
  | { type: "query"; secret: string; param: string }
  /** HTTP Basic. The secret holds "user:password". */
  | { type: "basic"; secret: string };

export interface ApiManifest {
  id: string;
  description: string;
  /** No trailing slash. Every request path is appended to this. */
  baseUrl: string;
  auth: AuthProvider;
  docs?: string;
  /** When false, only GET is permitted. */
  write: boolean;
  /**
   * Query params applied to every request unless the caller sets them.
   * Use this to pin anything the upstream would otherwise choose for us —
   * an API version, a response format — so a server-side default can't
   * silently change the response shape under us.
   */
  defaultQuery?: Record<string, string>;
  deny?: DenyRule[];
  /**
   * Provenance for the upstream API description this manifest was written from.
   * Used by `npm run check-drift` to notice when the API has moved on; never
   * read at runtime.
   */
  spec?: {
    source: string;
    packageVersion?: string;
    specVersion?: string;
    sha256?: string;
    retrieved?: string;
    file?: string;
  };
  /**
   * A cheap read used by check_auth to prove the credential works. Give an
   * `expectStatus` when the natural probe is not a 200 — e.g. an API with no
   * cheap list endpoint can ask for a fake id and expect 404.
   */
  probe?: {
    path: string;
    query?: Record<string, string | number>;
    expectStatus?: number;
    /**
     * What a passing probe actually demonstrates. Default "credential" means the
     * endpoint rejects unauthenticated callers, so success proves the stored
     * credential works. Use "reachability" when the cheapest safe endpoint is
     * unauthenticated — check_auth then says so rather than implying more than
     * it verified.
     */
    validates?: "credential" | "reachability";
  };
  endpoints: Endpoint[];
}

export interface Env {
  /**
   * Shared secret guarding this server, accepted as a Bearer header or a URL
   * path segment. Any additional secret named PERSONAL_MCP_TOKEN_* is accepted
   * too, so each client can hold its own token and be revoked on its own.
   */
  PERSONAL_MCP_TOKEN: string;
  [key: string]: unknown;
  /** The identity provider behind the Connect flow (src/oauth.ts). */
  OAUTH_AUTHORIZE_URL?: string;
  OAUTH_TOKEN_URL?: string;
  OAUTH_CLIENT_ID?: string;
  OAUTH_CLIENT_SECRET?: string;
  /** Space-separated. Defaults to "openid email". */
  OAUTH_SCOPES?: string;
  /** Extra authorize-URL parameters as a query string, e.g. "prompt=select_account". */
  OAUTH_AUTHORIZE_PARAMS?: string;
  /** Where to look up who signed in, for providers without an OIDC id_token. */
  OAUTH_USERINFO_URL?: string;
  /** The claim that names the account. Defaults to "email". */
  OAUTH_USER_CLAIM?: string;
  /** Comma-separated accounts allowed to log in. Login is refused without it. */
  OAUTH_ALLOWED_USERS?: string;
  /** Base64 32-byte AES key protecting credentials stored in KV. */
  KV_ENCRYPTION_KEY?: string;
  OAUTH_KV?: KVNamespace;
  /**
   * Comma-separated hostnames a runtime-added API may target. Deliberately a
   * Worker secret, so the list changes only from a terminal — a client holding
   * the OAuth grant can add APIs, but only within it.
   */
  ALLOWED_NEW_HOSTS?: string;
  /**
   * Comma-separated hosts call_api may follow a redirect to ("*.example.org"
   * for subdomains). A plain var in wrangler.jsonc: hostnames aren't secret,
   * and a var is readable and diffable. Empty means no redirect is followed.
   */
  ALLOWED_REDIRECT_HOSTS?: string;
}
