import { isConfigured, resolveAuth } from "./auth";
import { callApi, describeError, type CallResult } from "./call";
import {
  allowedNewHosts,
  allowedRedirectHosts,
  applyOverlay,
  getEffectiveApi,
  isAdded,
  knownIds,
  readOverlay,
  validateAddition,
  writeOverlay,
} from "./config";
import { MIN_TOKEN_LENGTH } from "./legacy-auth";
import { APIS } from "./registry";
import type { Env } from "./types";

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = { name: "wildcard-api-mcp", version: "1.0.0" };

export const TOOLS = [
  {
    name: "list_apis",
    description:
      "List every API this server can reach, with a one-line description, whether writes are allowed, " +
      "and whether its credential is configured. Start here when you don't know what is available.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "describe_api",
    description:
      "Show the endpoints of one API: method, path, query parameters, request body shape, and usage notes. " +
      "Call this before call_api so you use the right path and parameter names.",
    inputSchema: {
      type: "object",
      properties: {
        api: { type: "string", description: "API id from list_apis, e.g. 'github'." },
        search: {
          type: "string",
          description: "Optional filter — only endpoints whose path, summary or notes contain this string.",
        },
      },
      required: ["api"],
      additionalProperties: false,
    },
  },
  {
    name: "call_api",
    description:
      "Make an HTTP request to one of the configured APIs. Credentials are attached by the server; never " +
      "put tokens in the arguments. Returns the status line and the raw response body.",
    inputSchema: {
      type: "object",
      properties: {
        api: { type: "string", description: "API id from list_apis." },
        method: {
          type: "string",
          enum: ["GET", "POST", "PUT", "PATCH", "DELETE"],
          description: "Defaults to GET.",
        },
        path: {
          type: "string",
          description:
            "Path appended to the API's base URL, e.g. '/users/{username}/repos'. Substitute real ids " +
            "for {placeholders}. Do not include the host or a query string.",
        },
        query: {
          type: "object",
          description: "Query parameters. A value may be an array to repeat the key.",
          additionalProperties: true,
        },
        body: {
          type: "object",
          description: "JSON request body for POST/PUT/PATCH.",
          additionalProperties: true,
        },
        max_chars: {
          type: "integer",
          description: "Truncate the response body at this many characters. Default 30000, max 200000.",
        },
      },
      required: ["api", "path"],
      additionalProperties: false,
    },
  },
  {
    name: "check_auth",
    description:
      "Verify each configured credential by making a live call. Use this when a request fails with 401/403 " +
      "to tell a bad credential apart from a bad request.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_config",
    description:
      "Show this server's current configuration: every API it knows about, whether each is enabled, its " +
      "auth type, whether that credential is present, and which guardrails apply. Reports only whether " +
      "secrets are set, never their values.",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["text", "json"],
          description: "'text' (default) is readable prose; 'json' is the same facts as structured data, for a UI.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "set_config",
    description:
      "Switch an API off or back on. A disabled API leaves list_apis, stops resolving in describe_api, and " +
      "is refused by call_api — the practical equivalent of removing it, and reversible with 'enable'. " +
      "The setting is stored in eventually-consistent storage, so it can take up to a minute to apply " +
      "everywhere; it is a housekeeping control, NOT an emergency kill switch. To stop an API immediately, " +
      "revoke its credential or deploy. Base URLs, credentials and deny rules are not editable here.",
    inputSchema: {
      type: "object",
      properties: {
        action: { type: "string", enum: ["disable", "enable"], description: "What to do with the ids." },
        apis: {
          type: "array",
          items: { type: "string" },
          description: "API ids, as shown by get_config.",
        },
      },
      required: ["action", "apis"],
      additionalProperties: false,
    },
  },
  {
    name: "add_api",
    description:
      "Register a new API on this server, live, without a deploy. The manifest is the same shape as an " +
      "entry in apis.json. The base URL's host must already be on the server's allowed list, which only " +
      "changes from a terminal. Credentials are NOT set here — name a Worker secret (API_*) and set its " +
      "value separately; until then the API is registered but unusable.",
    inputSchema: {
      type: "object",
      properties: {
        manifest: {
          type: "object",
          description:
            "id, description, baseUrl (https, no trailing slash), write (boolean), auth, endpoints[], " +
            "optional docs/probe/deny/defaultQuery. auth is 'none' or " +
            "{type: bearer|header|query|basic, secret: 'API_NAME', ...}.",
          additionalProperties: true,
        },
      },
      required: ["manifest"],
      additionalProperties: false,
    },
  },
  {
    name: "remove_api",
    description:
      "Delete a runtime-added API outright. Bundled APIs cannot be deleted this way — they live in the " +
      "deployed bundle; use set_config to disable one instead.",
    inputSchema: {
      type: "object",
      properties: { api: { type: "string", description: "API id, as shown by get_config." } },
      required: ["api"],
      additionalProperties: false,
    },
  },
] as const;

async function listApis(env: Env): Promise<string> {
  const apis = applyOverlay(await readOverlay(env));
  if (!apis.length) return "No APIs are enabled. Call get_config to see what is switched off.";
  const rows = apis.map((api) => {
    const configured = isConfigured(api, env) ? "configured" : "NOT CONFIGURED";
    const access = api.write ? "read+write" : "read-only";
    return `- **${api.id}** — ${api.description}\n  ${access} · ${configured} · ${api.endpoints.length} endpoints`;
  });
  return `${rows.join("\n")}\n\nCall describe_api with an id to see its endpoints.`;
}

async function describeApi(env: Env, id: string, search?: string): Promise<string> {
  const api = await getEffectiveApi(env, id);
  if (!api) return `Unknown api '${id}'. Call list_apis to see what is available.`;

  const needle = search?.toLowerCase();
  const endpoints = needle
    ? api.endpoints.filter((e) =>
        `${e.path} ${e.summary} ${e.notes ?? ""} ${(e.query ?? []).join(" ")}`.toLowerCase().includes(needle),
      )
    : api.endpoints;

  if (!endpoints.length) return `No endpoints in '${id}' match '${search}'.`;

  const lines = endpoints.map((e) => {
    const parts = [`### ${e.method} ${e.path}`, e.summary];
    if (e.query?.length) parts.push(`query: ${e.query.join(", ")}`);
    if (e.body) parts.push(`body: ${e.body}`);
    if (e.notes) parts.push(`note: ${e.notes}`);
    return parts.join("\n");
  });

  const header = [
    `# ${api.id}`,
    api.description,
    `base URL: ${api.baseUrl}`,
    api.docs ? `docs: ${api.docs}` : null,
    api.write ? "writes: allowed" : "writes: blocked (GET only)",
    api.deny?.length ? `blocked: ${api.deny.map((d) => `${d.method} ${d.path}`).join(", ")}` : null,
    api.defaultQuery
      ? `pinned query defaults (override by passing the same key): ${Object.entries(api.defaultQuery)
          .map(([k, v]) => `${k}=${v}`)
          .join(", ")}`
      : null,
  ]
    .filter(Boolean)
    .join("\n");

  return `${header}\n\n${lines.join("\n\n")}`;
}


async function checkAuth(env: Env): Promise<string> {
  const results: string[] = [];
  const overlay = await readOverlay(env);

  // A disabled API is not probed, so without these lines it would simply be
  // absent from this report -- and this report is the first thing run when
  // something misbehaves. Silence would read as "no such API" rather than
  // "you switched it off".
  if (overlay.degraded) {
    results.push(
      `- CONFIG UNREADABLE (${overlay.degraded}) — every API below is live, including any you had disabled`,
    );
  }
  for (const id of overlay.disabled) {
    results.push(`- ${id}: DISABLED via set_config — not probed`);
  }

  for (const api of applyOverlay(overlay)) {
    if (!isConfigured(api, env)) {
      results.push(`- ${api.id}: not configured`);
      continue;
    }

    const probe = api.probe;
    if (!probe) {
      results.push(`- ${api.id}: configured (no probe defined)`);
      continue;
    }

    try {
      const out = await callApi({ api: api.id, path: probe.path, query: probe.query, max_chars: 400 }, env);
      const status = out.status;
      const expected = probe.expectStatus ?? 200;

      if (status === expected) {
        results.push(
          probe.validates === "reachability"
            ? `- ${api.id}: reachable (${status}) — endpoint needs no credential, so this does NOT prove the stored one works`
            : `- ${api.id}: ok (${status})`,
        );
      } else if (status === 401 || status === 403) {
        results.push(`- ${api.id}: ${status} — credential rejected or scope not granted`);
      } else {
        results.push(`- ${api.id}: unexpected ${status} (expected ${expected})`);
      }
    } catch (err) {
      results.push(`- ${api.id}: FAILED — ${describeError(err)}`);
    }
  }

  return results.join("\n");
}

/** Whether a named Worker secret is present — never its value. */
/** Every MCP_TOKEN* secret by name, flagging any too short to be accepted. */
function legacyTokenStatus(env: Env): string {
  const names = Object.keys(env)
    .filter((k) => k.startsWith("MCP_TOKEN") && secretPresent(env, k))
    .sort();
  if (!names.length) return "not set";
  return names
    .map((k) =>
      String(env[k]).length < MIN_TOKEN_LENGTH ? `${k} set but IGNORED — shorter than ${MIN_TOKEN_LENGTH} characters` : `${k} set`,
    )
    .join("; ");
}

function secretPresent(env: Env, name: string): boolean {
  return typeof env[name] === "string" && !!env[name];
}

function authLabel(api: (typeof APIS)[number]): string {
  return typeof api.auth === "object" ? `${api.auth.type} (secret ${api.auth.secret})` : api.auth;
}

async function getConfig(env: Env): Promise<string> {
  const overlay = await readOverlay(env);
  const { disabled, degraded: disabledUnreadable } = overlay;

  const rows = [...APIS, ...overlay.added].map((api) => {
    const off = disabled.includes(api.id);
    const flags = [
      off ? "DISABLED" : "enabled",
      isAdded(overlay, api.id) ? "added at runtime" : "bundled",
      api.write ? "read+write" : "read-only",
      isConfigured(api, env) ? "credential set" : "NO CREDENTIAL",
    ];
    const guards: string[] = [];
    if (api.deny?.length) guards.push(`${api.deny.length} deny rule${api.deny.length === 1 ? "" : "s"}`);
    if (!api.write) guards.push("GET only");
    return [
      `- **${api.id}** — ${flags.join(" · ")}`,
      `  host ${new URL(api.baseUrl).host} · auth ${authLabel(api)} · ${api.endpoints.length} endpoints`,
      guards.length ? `  guardrails: ${guards.join(", ")}` : null,
    ]
      .filter(Boolean)
      .join("\n");
  });

  const hosts = allowedNewHosts(env);
  const server = [
    `storage: ${env.OAUTH_KV ? "KV bound" : "NO KV BOUND — set_config cannot save"}`,
    `hosts allowed for add_api: ${hosts.length ? hosts.join(", ") : "NONE — add_api is refused until ALLOWED_NEW_HOSTS is set"}`,
    `hosts call_api may follow a redirect to: ${allowedRedirectHosts(env).join(", ") || "NONE — redirects are returned, not followed"}`,
    `KV encryption key: ${secretPresent(env, "KV_ENCRYPTION_KEY") ? "set" : "not set"}`,
    `legacy shared token: ${legacyTokenStatus(env)}`,
  ];

  const banner = disabledUnreadable
    ? [
        `> **Configuration could not be read — ${disabledUnreadable}.**`,
        "> Every API is live right now regardless of what was disabled, and set_config will refuse to write until this clears.",
        "",
      ].join("\n")
    : null;

  return [
    banner,
    "# APIs",
    rows.join("\n"),
    "",
    "# Server",
    server.map((l) => `- ${l}`).join("\n"),
    "",
    "Bundled APIs can be disabled but not deleted; added ones can be removed outright. Credentials are never set " +
      "from here — an added API names a Worker secret (API_*) whose value you set from a terminal.",
  ]
    .filter((l) => l !== null)
    .join("\n");
}

/**
 * The same facts as getConfig, structured. Kept beside it deliberately: a UI
 * parsing the prose version would break the first time that wording changed.
 */
async function getConfigJson(env: Env): Promise<string> {
  const overlay = await readOverlay(env);
  const apis = [...APIS, ...overlay.added].map((api) => ({
    id: api.id,
    description: api.description,
    baseUrl: api.baseUrl,
    host: new URL(api.baseUrl).host,
    enabled: !overlay.disabled.includes(api.id),
    source: isAdded(overlay, api.id) ? "added" : "bundled",
    removable: isAdded(overlay, api.id),
    write: api.write,
    configured: isConfigured(api, env),
    auth: typeof api.auth === "object" ? { type: api.auth.type, secret: api.auth.secret } : { type: api.auth },
    endpointCount: api.endpoints.length,
    denyRules: api.deny?.length ?? 0,
    docs: api.docs ?? null,
  }));

  return JSON.stringify(
    {
      apis,
      server: {
        storageBound: !!env.OAUTH_KV,
        allowedNewHosts: allowedNewHosts(env),
        allowedRedirectHosts: allowedRedirectHosts(env),
        kvEncryptionKeySet: secretPresent(env, "KV_ENCRYPTION_KEY"),
      },
      degraded: overlay.degraded ?? null,
    },
    null,
    2,
  );
}

async function setConfig(env: Env, action: string, apis: unknown): Promise<string> {
  if (action !== "disable" && action !== "enable") {
    throw new Error(`Unknown action '${action}'. Use 'disable' or 'enable'.`);
  }
  const ids = Array.isArray(apis) ? apis.map(String) : [];
  if (!ids.length) throw new Error("Pass at least one api id.");

  const overlay = await readOverlay(env);
  // Writing now would rebuild the list from an empty base and silently drop
  // whatever is actually stored, turning a transient read error into permanent
  // loss. Refuse instead.
  if (overlay.degraded) {
    throw new Error(
      `Refusing to write: the stored configuration could not be read (${overlay.degraded}). ` +
        "Nothing has changed. Resolve that first, or the existing disable list would be overwritten.",
    );
  }

  // A typo here would otherwise silently do nothing, or sit in the overlay as
  // a tombstone for an id that never existed.
  const known = knownIds(overlay);
  const unknown = ids.filter((id) => !known.includes(id));
  if (unknown.length) {
    throw new Error(`Unknown api ${unknown.map((i) => `'${i}'`).join(", ")}. Known: ${known.join(", ")}.`);
  }
  const before = new Set(overlay.disabled.filter((id) => known.includes(id)));
  const after = new Set(before);
  for (const id of ids) {
    if (action === "disable") after.add(id);
    else after.delete(id);
  }

  const changed = ids.filter((id) => before.has(id) !== after.has(id));
  if (!changed.length) {
    return `No change — ${ids.join(", ")} already ${action === "disable" ? "disabled" : "enabled"}.`;
  }

  await writeOverlay(env, { ...overlay, disabled: [...after].sort() });

  const still = [...after].sort();
  return [
    `${action === "disable" ? "Disabled" : "Enabled"}: ${changed.join(", ")}.`,
    still.length ? `Now disabled: ${still.join(", ")}.` : "Nothing is disabled now.",
    action === "disable"
      ? "These are gone from list_apis and refused by call_api. Re-enable them with set_config."
      : null,
  ]
    .filter(Boolean)
    .join("\n");
}

async function addApi(env: Env, manifest: unknown): Promise<string> {
  const overlay = await readOverlay(env);
  if (overlay.degraded) {
    throw new Error(
      `Refusing to write: the stored configuration could not be read (${overlay.degraded}). Nothing has changed.`,
    );
  }

  const api = validateAddition(env, manifest, overlay);
  await writeOverlay(env, { ...overlay, added: [...overlay.added, api] });

  const secret = typeof api.auth === "object" ? api.auth.secret : null;
  return [
    `Added **${api.id}** — ${api.endpoints.length} endpoint${api.endpoints.length === 1 ? "" : "s"} on ${new URL(api.baseUrl).host}, ${api.write ? "read+write" : "read-only"}.`,
    "It is live now; no deploy needed.",
    secret
      ? `It has no credential yet. Set one with \`npm run secret -- put ${secret}\` and it will start working — check_auth will say "not configured" until then.`
      : "It needs no credential.",
  ].join("\n");
}

async function removeApi(env: Env, id: string): Promise<string> {
  const overlay = await readOverlay(env);
  if (overlay.degraded) {
    throw new Error(
      `Refusing to write: the stored configuration could not be read (${overlay.degraded}). Nothing has changed.`,
    );
  }

  if (!isAdded(overlay, id)) {
    const bundled = APIS.some((a) => a.id === id);
    throw new Error(
      bundled
        ? `'${id}' is built into the deployed bundle and cannot be deleted here. Disable it with set_config instead.`
        : `Unknown api '${id}'.`,
    );
  }

  await writeOverlay(env, {
    ...overlay,
    added: overlay.added.filter((a) => a.id !== id),
    // Drop any tombstone too, so a later API reusing the id is not born disabled.
    disabled: overlay.disabled.filter((d) => d !== id),
  });
  const secret = overlay.added.find((a) => a.id === id)?.auth;
  const name = typeof secret === "object" ? secret.secret : null;
  return [
    `Removed **${id}**.`,
    name ? `Its credential secret ${name} is still set on the Worker; delete it with \`npm run secret -- delete ${name}\` if nothing else uses it.` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

async function runTool(name: string, args: Record<string, any>, env: Env): Promise<CallResult> {
  // Only call_api can return an image; every other tool is text, wrapped here so
  // the transport has a single shape to render.
  const asText = (text: string): CallResult => ({ status: 0, text });
  switch (name) {
    case "list_apis":
      return asText(await listApis(env));
    case "describe_api":
      return asText(await describeApi(env, String(args.api), args.search ? String(args.search) : undefined));
    case "call_api":
      return await callApi(args as any, env);
    case "check_auth":
      return asText(await checkAuth(env));
    case "get_config":
      return asText(args.format === "json" ? await getConfigJson(env) : await getConfig(env));
    case "set_config":
      return asText(await setConfig(env, String(args.action), args.apis as unknown));
    case "add_api":
      return asText(await addApi(env, args.manifest));
    case "remove_api":
      return asText(await removeApi(env, String(args.api)));
    default:
      throw new Error(`Unknown tool '${name}'.`);
  }
}

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: any;
}

function result(id: any, value: unknown) {
  return { jsonrpc: "2.0" as const, id, result: value };
}

function error(id: any, code: number, message: string) {
  return { jsonrpc: "2.0" as const, id, error: { code, message } };
}

/** Returns null for notifications, which take no response body. */
export async function handleRpc(req: JsonRpcRequest, env: Env): Promise<object | null> {
  const { id, method, params } = req;

  switch (method) {
    case "initialize":
      return result(id, {
        protocolVersion: PROTOCOL_VERSION,
        // true, because the list genuinely does change now: add_api and
        // remove_api alter what this server exposes between one connect and
        // the next. Declaring false told clients the set was fixed, which is
        // a reason a cached list can outlive a deploy.
        capabilities: { tools: { listChanged: true } },
        serverInfo: SERVER_INFO,
      });

    case "notifications/initialized":
    case "notifications/cancelled":
      return null;

    case "ping":
      return result(id, {});

    case "tools/list":
      return result(id, { tools: TOOLS });

    case "tools/call": {
      const name = params?.name;
      const args = params?.arguments ?? {};
      try {
        const out = await runTool(name, args, env);
        // The text block always carries the status line and any body/caption; an
        // image block is appended only when the upstream actually returned one.
        const content: object[] = [{ type: "text", text: out.text }];
        if (out.image) content.push({ type: "image", data: out.image.data, mimeType: out.image.mimeType });
        return result(id, { content });
      } catch (err) {
        // Errors belong in the result as isError, so the model can read them
        // and correct the call itself.
        return result(id, { content: [{ type: "text", text: describeError(err) }], isError: true });
      }
    }

    // Declared unsupported rather than left to 404, so clients that probe
    // during handshake don't treat the server as broken.
    case "resources/list":
      return result(id, { resources: [] });
    case "prompts/list":
      return result(id, { prompts: [] });

    default:
      return error(id, -32601, `Method not found: ${method}`);
  }
}
