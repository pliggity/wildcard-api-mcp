/**
 * Adversarial tests: each one is an attack on a guardrail, and passes only if
 * the guardrail holds. They drive the real handlers with a fake env, an
 * in-memory KV and a stubbed fetch that records every outbound request, so a
 * test can assert not just "the call errored" but "nothing left the Worker".
 *
 * APIs are registered through add_api rather than apis.json, which keeps the
 * bundle empty and exercises the runtime-addition gate on the way.
 */
import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index";
import { handleRpc } from "../src/mcp";
import { oauthHandler } from "../src/oauth";
import { oauthMcpHandler } from "../src/mcp-handler";

// ------------------------------------------------------------------ fakes

class MemoryKV {
  map = new Map<string, string>();
  async get(key: string, type?: string) {
    const v = this.map.get(key);
    if (v === undefined) return null;
    return type === "json" ? JSON.parse(v) : v;
  }
  async put(key: string, value: string) {
    this.map.set(key, value);
  }
  async delete(key: string) {
    this.map.delete(key);
  }
}

interface Seen {
  url: string;
  init: RequestInit;
}

let seen: Seen[] = [];
function stubFetch(responder: (url: string, init: RequestInit) => Response | Promise<Response>) {
  seen = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    seen.push({ url, init });
    return responder(url, init);
  }) as typeof fetch;
}

const TOKEN = "t".repeat(32);

function makeEnv(extra: Record<string, unknown> = {}): any {
  return {
    PERSONAL_MCP_TOKEN: TOKEN,
    OAUTH_KV: new MemoryKV(),
    ALLOWED_NEW_HOSTS: "api.test,other.test",
    API_KEY: "sekrit",
    API_OTHER: "other-sekrit",
    ...extra,
  };
}

async function tool(env: any, name: string, args: Record<string, unknown>) {
  const res: any = await handleRpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, env);
  return { text: res.result.content[0].text as string, isError: !!res.result.isError, content: res.result.content };
}

function manifest(over: Record<string, unknown> = {}) {
  return {
    id: "svc",
    description: "test service",
    baseUrl: "https://api.test/v1",
    write: true,
    auth: { type: "bearer", secret: "API_KEY" },
    endpoints: [{ method: "GET", path: "/x", summary: "x" }],
    deny: [
      { method: "*", path: "/admin/**", reason: "no admin" },
      { method: "*", path: "/admin", reason: "no admin" },
    ],
    ...over,
  };
}

async function envWithApi(over: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) {
  const env = makeEnv(extra);
  const added = await tool(env, "add_api", { manifest: manifest(over) });
  assert.equal(added.isError, false, added.text);
  return env;
}

function mcpRequest(body: unknown, headers: Record<string, string> = {}, path = "/mcp") {
  return new Request(`https://worker.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const ctx = { waitUntil() {}, passThroughOnException() {} } as any;

beforeEach(() => stubFetch(() => new Response("ok", { headers: { "content-type": "text/plain" } })));

// ------------------------------------------------------- deny-rule bypass

describe("deny rules cannot be sidestepped by path tricks", () => {
  const reachedAdmin = () =>
    seen.some((s) => {
      const p = new URL(s.url).pathname;
      return decodeURIComponent(p).toLowerCase().startsWith("/v1/admin");
    });

  const tricks = [
    ["plain", "/admin/users"],
    ["percent-encoded dot segment", "/x/%2e%2e/admin/users"],
    ["mixed-case encoded dots", "/x/.%2E/admin/users"],
    ["backslash dot segment", "/x\\..\\admin/users"],
    ["tab inside dot segment", "/x/.\t./admin/users"],
    ["newline inside dot segment", "/x/\n../admin/users"],
    ["single dot segment", "/./admin/users"],
    ["fragment after exact path", "/admin#anything"],
    ["query after exact path", "/admin?x=1"],
    ["percent-encoded letter", "/%61dmin/users"],
    ["encoded slash", "/admin%2Fusers"],
    ["trailing slash on an exact rule", "/admin/"],
    ["doubled slash in the middle", "/admin//users"],
    ["empty segment before the target", "/./admin"],
    ["different case", "/Admin/users"],
    ["different case on an exact rule", "/ADMIN"],
    ["path parameter on a segment", "/admin;x/users"],
    ["encoded path parameter", "/admin%3Bx/users"],
    ["path parameter on an exact rule", "/admin;jsessionid=1"],
  ];

  for (const [name, path] of tricks) {
    test(name, async () => {
      const env = await envWithApi();
      seen = [];
      const r = await tool(env, "call_api", { api: "svc", method: "DELETE", path });
      assert.equal(reachedAdmin(), false, `request reached ${seen.map((s) => s.url).join(", ")}`);
      assert.equal(r.isError, true, r.text);
    });
  }

  // The shape of the Drive "no sharing" rule in example.apis.json.
  for (const path of [
    "/files/abc/permissions",
    "/files/abc/permissions/",
    "/files/abc//permissions",
    "/files//abc/permissions",
    "/files/abc/x/%2e%2e/permissions",
    "/files/abc/%70ermissions",
  ]) {
    test(`single-segment rule holds for ${path}`, async () => {
      const env = await envWithApi({ deny: [{ method: "POST", path: "/files/*/permissions", reason: "no sharing" }] });
      seen = [];
      const r = await tool(env, "call_api", { api: "svc", method: "POST", path, body: { role: "writer" } });
      assert.equal(r.isError, true, r.text);
      assert.equal(seen.length, 0, `request reached ${seen.map((s) => s.url).join(", ")}`);
    });
  }

  test("an allowed path still goes through", async () => {
    const env = await envWithApi();
    seen = [];
    const r = await tool(env, "call_api", { api: "svc", path: "/x/items", query: { q: "a b" } });
    assert.equal(r.isError, false, r.text);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, "https://api.test/v1/x/items?q=a+b");
  });
});

describe("requests stay inside the manifest's base URL", () => {
  test("a dot segment cannot reach a sibling path that shares the base's prefix", async () => {
    const env = await envWithApi();
    seen = [];
    const r = await tool(env, "call_api", { api: "svc", path: "/%2e%2e/v1beta/secrets" });
    assert.equal(seen.length, 0, `request reached ${seen.map((s) => s.url).join(", ")}`);
    assert.equal(r.isError, true);
  });

  test("a dot segment cannot climb above the base path", async () => {
    const env = await envWithApi();
    seen = [];
    const r = await tool(env, "call_api", { api: "svc", path: "/x/%2e%2e/%2e%2e/other" });
    assert.equal(seen.length, 0);
    assert.equal(r.isError, true);
  });

  test("redirects are not followed, so an upstream open redirect can't send the request elsewhere", async () => {
    const env = await envWithApi();
    stubFetch(() => new Response(null, { status: 302, headers: { location: "https://evil.test/steal" } }));
    const r = await tool(env, "call_api", { api: "svc", path: "/x" });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].init.redirect, "manual");
    assert.match(r.text, /302/);
    assert.match(r.text, /evil\.test/, "the model should see where it was redirected");
  });

  test("read-only APIs refuse every non-GET method", async () => {
    const env = await envWithApi({ write: false });
    seen = [];
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "post"]) {
      const r = await tool(env, "call_api", { api: "svc", method, path: "/x" });
      assert.equal(r.isError, true, method);
    }
    assert.equal(seen.length, 0);
  });
});

// ------------------------------------------------------ credential handling

describe("credentials", () => {
  test("a caller cannot replace the query-param credential with its own value", async () => {
    const env = await envWithApi({ auth: { type: "query", secret: "API_KEY", param: "key" } });
    seen = [];
    await tool(env, "call_api", { api: "svc", path: "/x", query: { key: "attacker" } });
    assert.deepEqual(new URL(seen[0].url).searchParams.getAll("key"), ["sekrit"]);
  });

  test("a caller cannot smuggle a second credential param through the path", async () => {
    const env = await envWithApi({ auth: { type: "query", secret: "API_KEY", param: "key" } });
    seen = [];
    const r = await tool(env, "call_api", { api: "svc", path: "/x?key=attacker" });
    assert.equal(r.isError, true, r.text);
    assert.equal(seen.length, 0, `request reached ${seen.map((s) => s.url).join(", ")}`);
  });

  test("a query-param credential never appears in what call_api returns", async () => {
    const secret = "sekrit-query-value";
    const env = await envWithApi({ auth: { type: "query", secret: "API_KEY", param: "key" } }, { API_KEY: secret });
    stubFetch((url) => new Response(`you sent ${url}`, { headers: { "content-type": "text/plain" } }));
    const ok = await tool(env, "call_api", { api: "svc", path: "/x" });
    assert.equal(new URL(seen[0].url).searchParams.get("key"), secret, "the upstream still gets the credential");
    assert.doesNotMatch(ok.text, /sekrit/);
    stubFetch(() => new Response(null, { status: 302, headers: { location: `https://api.test/v1/y?key=${secret}` } }));
    const redirected = await tool(env, "call_api", { api: "svc", path: "/x" });
    assert.doesNotMatch(redirected.text, /sekrit/);
  });

  test("the status line is built without the credential, not masked after the fact", async () => {
    // Too short for the redactor to touch, so only the structure keeps it out.
    const env = await envWithApi({ auth: { type: "query", secret: "API_KEY", param: "key" } }, { API_KEY: "k3y" });
    const r = await tool(env, "call_api", { api: "svc", path: "/x", query: { q: "1" } });
    assert.equal(new URL(seen[0].url).searchParams.get("key"), "k3y");
    assert.match(r.text, /GET \/v1\/x\?q=1 /);
    assert.doesNotMatch(r.text, /key=/);
  });

  test("a header credential echoed in a response body is redacted", async () => {
    const env = await envWithApi({}, { API_KEY: "sekrit-bearer-value" });
    stubFetch((_url, init) =>
      new Response(`echo: ${(init.headers as Record<string, string>).authorization}`, {
        headers: { "content-type": "text/plain" },
      }),
    );
    const r = await tool(env, "call_api", { api: "svc", path: "/x" });
    assert.doesNotMatch(r.text, /sekrit/);
  });

  test("a runtime-added API on the same host cannot move an existing secret into a query param", async () => {
    const env = await envWithApi();
    for (const auth of [
      { type: "query", secret: "API_KEY", param: "k" },
      { type: "header", secret: "API_KEY", header: "x-echo" },
    ]) {
      const r = await tool(env, "add_api", {
        manifest: manifest({ id: "leak", baseUrl: "https://api.test/v2", deny: undefined, auth }),
      });
      assert.equal(r.isError, true, r.text);
    }
  });

  test("a runtime-added API cannot borrow another API's secret for a different host", async () => {
    const env = await envWithApi();
    const r = await tool(env, "add_api", {
      manifest: manifest({ id: "thief", baseUrl: "https://other.test", deny: undefined }),
    });
    assert.equal(r.isError, true, r.text);
  });

  test("two manifests on the same host may share a secret", async () => {
    const env = await envWithApi();
    const r = await tool(env, "add_api", {
      manifest: manifest({ id: "svc_v2", baseUrl: "https://api.test/v2", deny: undefined }),
    });
    assert.equal(r.isError, false, r.text);
  });

  test("runtime additions may not read a non-API_* secret", async () => {
    const env = makeEnv();
    const r = await tool(env, "add_api", {
      manifest: manifest({ auth: { type: "bearer", secret: "PERSONAL_MCP_TOKEN" } }),
    });
    assert.equal(r.isError, true);
  });

  for (const baseUrl of [
    "https://user:pw@api.test/v1",
    "https://api.test/v1?x=1",
    "https://api.test/v1#frag",
    "http://api.test/v1",
    "https://evil.test/v1",
    "https://api.test.evil.test/v1",
  ]) {
    test(`add_api refuses baseUrl ${baseUrl}`, async () => {
      const r = await tool(makeEnv(), "add_api", { manifest: manifest({ baseUrl }) });
      assert.equal(r.isError, true, r.text);
    });
  }

  test("add_api refuses a manifest too large to be a real API description", async () => {
    const endpoints = Array.from({ length: 5000 }, (_, i) => ({
      method: "GET",
      path: `/e${i}`,
      summary: "x".repeat(100),
    }));
    const r = await tool(makeEnv(), "add_api", { manifest: manifest({ endpoints }) });
    assert.equal(r.isError, true);
  });

  test("add_api refuses mistyped endpoint fields", async () => {
    const r = await tool(makeEnv(), "add_api", {
      manifest: manifest({ endpoints: [{ method: "GET", path: "/x", summary: "x", notes: { evil: true } }] }),
    });
    assert.equal(r.isError, true);
  });

  test("get_config flags every legacy token too short to be accepted", async () => {
    const r = await tool(makeEnv({ PERSONAL_MCP_TOKEN_PHONE: "short" }), "get_config", {});
    assert.match(r.text, /PERSONAL_MCP_TOKEN_PHONE set but IGNORED/);
    assert.doesNotMatch(r.text, /PERSONAL_MCP_TOKEN set but IGNORED/);
  });

  test("get_config and list_apis never print a secret's value", async () => {
    const env = await envWithApi();
    for (const name of ["get_config", "list_apis", "describe_api"]) {
      const r = await tool(env, name, { api: "svc" });
      assert.doesNotMatch(r.text, /sekrit|tttttttt/, name);
    }
    const json = await tool(env, "get_config", { format: "json" });
    assert.doesNotMatch(json.text, /sekrit|tttttttt/);
  });
});

// --------------------------------------------------------- resource limits

describe("responses are bounded", () => {
  function endless(chunk: Uint8Array, maxChunks: number, counter: { bytes: number }) {
    let n = 0;
    return new ReadableStream<Uint8Array>({
      pull(c) {
        if (n++ >= maxChunks) return c.close();
        counter.bytes += chunk.byteLength;
        c.enqueue(chunk);
      },
    });
  }

  test("a huge text body is not read into memory in full", async () => {
    const env = await envWithApi();
    const counter = { bytes: 0 };
    const MB = new Uint8Array(1 << 20).fill(97);
    stubFetch(() => new Response(endless(MB, 64, counter), { headers: { "content-type": "text/plain" } }));
    const r = await tool(env, "call_api", { api: "svc", path: "/x" });
    assert.ok(counter.bytes <= 4 << 20, `read ${counter.bytes} bytes`);
    assert.match(r.text, /truncated/);
  });

  test("a huge image is refused without reading it all", async () => {
    const env = await envWithApi();
    const counter = { bytes: 0 };
    const MB = new Uint8Array(1 << 20);
    stubFetch(() => new Response(endless(MB, 64, counter), { headers: { "content-type": "image/png" } }));
    const r = await tool(env, "call_api", { api: "svc", path: "/x" });
    assert.ok(counter.bytes <= 7 << 20, `read ${counter.bytes} bytes`);
    assert.equal(r.content.length, 1, "no image block");
  });

  test("max_chars that isn't a number can't lift the hard cap", async () => {
    const env = await envWithApi();
    stubFetch(() => new Response("a".repeat(300_000)));
    for (const max_chars of ["lots", -1, 1e12, null]) {
      const r = await tool(env, "call_api", { api: "svc", path: "/x", max_chars });
      assert.ok(r.text.length < 210_000, `max_chars=${max_chars} returned ${r.text.length}`);
    }
  });

  test("an oversized path is refused before any fetch", async () => {
    const env = await envWithApi();
    seen = [];
    const r = await tool(env, "call_api", { api: "svc", path: "/" + "a".repeat(5000) });
    assert.equal(r.isError, true);
    assert.equal(seen.length, 0);
  });

  test("adversarial paths don't make deny matching slow", async () => {
    const env = await envWithApi({ deny: [{ method: "*", path: "/**/**/**/**/**/z", reason: "r" }] });
    const started = Date.now();
    await tool(env, "call_api", { api: "svc", path: "/" + "a/".repeat(1000) });
    assert.ok(Date.now() - started < 200);
  });
});

// --------------------------------------------------------------- transport

describe("transport", () => {
  const auth = { authorization: `Bearer ${TOKEN}` };

  test("a null JSON-RPC message gets an error, not a crash", async () => {
    for (const body of ["null", "[null]", "[1, \"x\"]", "{}"]) {
      const res = await worker.fetch(mcpRequest(body, auth), makeEnv(), ctx);
      assert.ok(res.status < 500, `${body} → ${res.status}`);
    }
  });

  test("an oversized batch is refused before any tool runs", async () => {
    const env = await envWithApi();
    seen = [];
    const call = { jsonrpc: "2.0", method: "tools/call", params: { name: "call_api", arguments: { api: "svc", path: "/x" } } };
    const batch = Array.from({ length: 500 }, (_, id) => ({ ...call, id }));
    const res = await worker.fetch(mcpRequest(batch, auth), env, ctx);
    assert.equal(res.status, 400);
    assert.equal(seen.length, 0);
  });

  test("a malformed percent-escape in the token path does not crash the Worker", async () => {
    const res = await worker.fetch(mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" }, {}, "/mcp/%E0%A4%A"), makeEnv(), ctx);
    assert.ok(res.status === 401 || res.status === 404, String(res.status));
  });

  test("the legacy token works as a bearer header and as a path segment", async () => {
    const ping = { jsonrpc: "2.0", id: 1, method: "ping" };
    assert.equal((await worker.fetch(mcpRequest(ping, auth), makeEnv(), ctx)).status, 200);
    assert.equal((await worker.fetch(mcpRequest(ping, {}, `/mcp/${TOKEN}`), makeEnv(), ctx)).status, 200);
  });

  test("a wrong or missing token gets 401", async () => {
    const ping = { jsonrpc: "2.0", id: 1, method: "ping" };
    for (const headers of [{}, { authorization: "Bearer nope" }, { authorization: `Bearer ${TOKEN}x` }]) {
      const res = await worker.fetch(mcpRequest(ping, headers), makeEnv(), ctx);
      assert.equal(res.status, 401);
    }
  });

  test("a legacy token too short to be a real secret is never accepted", async () => {
    const ping = { jsonrpc: "2.0", id: 1, method: "ping" };
    const env = makeEnv({ PERSONAL_MCP_TOKEN: "abc" });
    const res = await worker.fetch(mcpRequest(ping, { authorization: "Bearer abc" }), env, ctx);
    assert.equal(res.status, 401);
  });

  test("an empty secret named PERSONAL_MCP_TOKEN_* does not open the door to an empty token", async () => {
    const ping = { jsonrpc: "2.0", id: 1, method: "ping" };
    const env = makeEnv({ PERSONAL_MCP_TOKEN: "", PERSONAL_MCP_TOKEN_OLD: "" });
    const res = await worker.fetch(mcpRequest(ping, { authorization: "Bearer " }), env, ctx);
    assert.equal(res.status, 401);
  });
});

// ------------------------------------------------------------------- OAuth

describe("OAuth", () => {
  const b64url = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const idToken = (claims: Record<string, unknown>) => `${b64url({ alg: "RS256" })}.${b64url(claims)}.sig`;

  function oauthEnv(extra: Record<string, unknown> = {}) {
    const calls: unknown[] = [];
    const env = makeEnv({
      OAUTH_AUTHORIZE_URL: "https://idp.test/authorize",
      OAUTH_TOKEN_URL: "https://idp.test/token",
      OAUTH_CLIENT_ID: "client-1",
      OAUTH_CLIENT_SECRET: "client-secret",
      OAUTH_ALLOWED_USERS: "owner@example.com",
      OAUTH_PROVIDER: {
        async completeAuthorization(opts: unknown) {
          calls.push(opts);
          return { redirectTo: "https://client.test/cb?code=x" };
        },
        async parseAuthRequest() {
          return { clientId: "c", redirectUri: "https://client.test/cb", scope: [], state: "s", responseType: "code" };
        },
        async lookupClient() {
          return { clientId: "c", clientName: "Client", redirectUris: ["https://client.test/cb"] };
        },
      },
      ...extra,
    });
    return { env, calls };
  }

  async function callback(env: any, tokenResponse: unknown) {
    await env.OAUTH_KV.put("pending-auth:abc", JSON.stringify({ req: { clientId: "c" }, verifier: "v" }));
    stubFetch((url) =>
      url.startsWith("https://idp.test/token")
        ? Response.json(tokenResponse)
        : Response.json({ login: "Owner", email: "owner@example.com" }),
    );
    return oauthHandler.fetch(
      new Request("https://worker.test/callback?code=c&state=abc", { headers: { cookie: "__Host-wildcard_oauth=abc" } }),
      env,
    );
  }

  test("a verified, pinned account completes authorization", async () => {
    const { env, calls } = oauthEnv();
    const res = await callback(env, {
      access_token: "a",
      id_token: idToken({ aud: "client-1", email: "owner@example.com", email_verified: true }),
    });
    assert.equal(res.status, 302);
    assert.equal(calls.length, 1);
  });

  const refused: [string, Record<string, unknown>][] = [
    ["an id_token without an audience", { email: "owner@example.com", email_verified: true }],
    ["an id_token for another client", { aud: "someone-else", email: "owner@example.com", email_verified: true }],
    ["email_verified as the string \"false\"", { aud: "client-1", email: "owner@example.com", email_verified: "false" }],
    ["an id_token that doesn't say the email is verified", { aud: "client-1", email: "owner@example.com" }],
    ["an account that isn't pinned", { aud: "client-1", email: "intruder@example.com", email_verified: true }],
  ];
  for (const [name, claims] of refused) {
    test(`refuses ${name}`, async () => {
      const { env, calls } = oauthEnv();
      const res = await callback(env, { access_token: "a", id_token: idToken(claims) });
      assert.notEqual(res.status, 302);
      assert.equal(calls.length, 0);
    });
  }

  test("a userinfo provider that doesn't say the email is verified can't pin by email", async () => {
    const { env, calls } = oauthEnv({ OAUTH_USERINFO_URL: "https://idp.test/user" });
    const res = await callback(env, { access_token: "a" });
    assert.notEqual(res.status, 302);
    assert.equal(calls.length, 0);
  });

  test("a userinfo response that isn't JSON gets an error page, not a Worker exception", async () => {
    const { env, calls } = oauthEnv({ OAUTH_USERINFO_URL: "https://idp.test/user" });
    await env.OAUTH_KV.put("pending-auth:abc", JSON.stringify({ req: { clientId: "c" }, verifier: "v" }));
    stubFetch((url) =>
      url.startsWith("https://idp.test/token")
        ? Response.json({ access_token: "a" })
        : new Response("<html>oops</html>", { headers: { "content-type": "text/html" } }),
    );
    const res = await oauthHandler.fetch(
      new Request("https://worker.test/callback?code=c&state=abc", { headers: { cookie: "__Host-wildcard_oauth=abc" } }),
      env,
    );
    assert.equal(res.status, 502);
    assert.equal(calls.length, 0);
  });

  test("a userinfo provider without email_verified (GitHub) still works by login", async () => {
    const { env, calls } = oauthEnv({
      OAUTH_USERINFO_URL: "https://idp.test/user",
      OAUTH_USER_CLAIM: "login",
      OAUTH_ALLOWED_USERS: "owner",
    });
    const res = await callback(env, { access_token: "a" });
    assert.equal(res.status, 302);
    assert.equal(calls.length, 1);
  });

  test("a callback without the browser's cookie is refused", async () => {
    const { env, calls } = oauthEnv();
    await env.OAUTH_KV.put("pending-auth:abc", JSON.stringify({ req: {}, verifier: "v" }));
    const res = await oauthHandler.fetch(new Request("https://worker.test/callback?code=c&state=abc"), env);
    assert.equal(res.status, 400);
    assert.equal(calls.length, 0);
  });

  test("a pending request can be completed only once", async () => {
    const { env } = oauthEnv();
    const token = { access_token: "a", id_token: idToken({ aud: "client-1", email: "owner@example.com", email_verified: true }) };
    await callback(env, token);
    const again = await oauthHandler.fetch(
      new Request("https://worker.test/callback?code=c&state=abc", { headers: { cookie: "__Host-wildcard_oauth=abc" } }),
      env,
    );
    assert.equal(again.status, 400);
  });

  test("an approval form posted without the matching cookie is refused", async () => {
    const { env } = oauthEnv();
    const form = new FormData();
    form.set("id", "abc");
    const res = await oauthHandler.fetch(new Request("https://worker.test/authorize", { method: "POST", body: form }), env);
    assert.equal(res.status, 400);
  });

  test("the approval screen can't be framed or cached, and escapes the client name", async () => {
    const { env } = oauthEnv();
    env.OAUTH_PROVIDER.lookupClient = async () => ({ clientName: "<script>alert(1)</script>" });
    const res = await oauthHandler.fetch(new Request("https://worker.test/authorize?client_id=c"), env);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.match(res.headers.get("cache-control") ?? "", /no-store/);
    assert.doesNotMatch(await res.text(), /<script>/);
  });

  test("a bad authorize request gets an error page, not a Worker exception", async () => {
    const { env } = oauthEnv();
    env.OAUTH_PROVIDER.parseAuthRequest = async () => {
      throw new Error("Invalid redirect URI");
    };
    const res = await oauthHandler.fetch(new Request("https://worker.test/authorize?client_id=c"), env);
    assert.equal(res.status, 400);
  });

  test("an OAuth grant stops working once its account is removed from OAUTH_ALLOWED_USERS", async () => {
    const ping = mcpRequest({ jsonrpc: "2.0", id: 1, method: "ping" });
    const { env } = oauthEnv();
    const ok = await oauthMcpHandler.fetch(ping.clone(), env, { ...ctx, props: { user: "owner@example.com" } });
    assert.equal(ok.status, 200);
    const gone = await oauthMcpHandler.fetch(ping.clone(), env, { ...ctx, props: { user: "former@example.com" } });
    assert.equal(gone.status, 403);
  });
});
