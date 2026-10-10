import { DENY_PRESETS } from "./deny-presets";
import type { ApiManifest, DenyRule, Endpoint, HttpMethod } from "./types";

/**
 * Checks apis.json at load time, replacing what the type checker used to catch.
 * Errors name the API and the field, because a typo here is otherwise a
 * confusing runtime failure much later.
 */

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const AUTH_TYPES = ["bearer", "header", "query", "basic"];

function fail(where: string, message: string): never {
  throw new Error(`apis.json — ${where}: ${message}`);
}

function validateEndpoint(apiId: string, e: any, i: number): Endpoint {
  const where = `${apiId}.endpoints[${i}]`;
  if (!e || typeof e !== "object") fail(where, "must be an object");
  if (!METHODS.includes(e.method)) fail(where, `method must be one of ${METHODS.join(", ")}, got ${JSON.stringify(e.method)}`);
  if (typeof e.path !== "string" || !e.path.startsWith("/")) fail(where, "path must be a string starting with '/'");
  if (typeof e.summary !== "string" || !e.summary) fail(where, "summary is required");
  if (e.query !== undefined && !(Array.isArray(e.query) && e.query.every((q: unknown) => typeof q === "string"))) {
    fail(where, "query must be an array of parameter names");
  }
  // These are rendered into describe_api, so anything but a string is a mistake.
  for (const field of ["body", "notes"]) {
    if (e[field] !== undefined && typeof e[field] !== "string") fail(where, `${field} must be a string`);
  }
  return e as Endpoint;
}

function resolveDeny(apiId: string, deny: any): DenyRule[] | undefined {
  if (deny === undefined) return undefined;
  if (typeof deny === "string") {
    const preset = DENY_PRESETS[deny];
    if (!preset) {
      fail(`${apiId}.deny`, `unknown preset ${JSON.stringify(deny)}; known: ${Object.keys(DENY_PRESETS).join(", ")}`);
    }
    return preset;
  }
  if (!Array.isArray(deny)) fail(`${apiId}.deny`, "must be a preset name or an array of rules");
  deny.forEach((r: any, i: number) => {
    const where = `${apiId}.deny[${i}]`;
    if (!r || typeof r !== "object") fail(where, "must be an object");
    if (r.method !== "*" && !METHODS.includes(r.method)) fail(where, `method must be "*" or one of ${METHODS.join(", ")}`);
    if (typeof r.path !== "string") fail(where, "path is required");
    if (typeof r.reason !== "string" || !r.reason) fail(where, "reason is required — it is shown to the caller");
  });
  return deny as DenyRule[];
}

export function validateManifests(raw: unknown): ApiManifest[] {
  if (!Array.isArray(raw)) fail("root", "must be an array of API manifests");

  const seen = new Set<string>();
  return raw.map((a: any, index: number) => {
    const id = typeof a?.id === "string" ? a.id : `[${index}]`;
    if (!a || typeof a !== "object") fail(id, "must be an object");
    if (!/^[a-z][a-z0-9_]*$/.test(a.id ?? "")) fail(id, "id must be lowercase letters, digits and underscores");
    if (seen.has(a.id)) fail(id, "duplicate id");
    seen.add(a.id);

    if (typeof a.description !== "string" || !a.description) fail(id, "description is required");
    if (typeof a.baseUrl !== "string") fail(id, "baseUrl is required");
    try {
      new URL(a.baseUrl);
    } catch {
      fail(id, `baseUrl is not a valid URL: ${a.baseUrl}`);
    }
    if (a.baseUrl.endsWith("/")) fail(id, "baseUrl must not end with '/'");
    const base = new URL(a.baseUrl);
    // Every request is built by appending to this string, so a query, fragment
    // or userinfo here would corrupt or redirect every call made through it.
    if (base.username || base.password || a.baseUrl.includes("?") || a.baseUrl.includes("#")) {
      fail(id, "baseUrl must be a plain scheme://host/path, with no credentials, query or fragment");
    }
    if (base.protocol !== "https:" && base.protocol !== "http:") fail(id, "baseUrl must be http(s)");
    // A credential sent over plain http is readable by anyone on the path.
    if (base.protocol === "http:" && typeof a.auth === "object") fail(id, "baseUrl must be https when auth sends a credential");
    if (typeof a.write !== "boolean") fail(id, "write must be true or false — state it explicitly");
    if (a.docs !== undefined && typeof a.docs !== "string") fail(id, "docs must be a string");
    if (a.defaultQuery !== undefined) {
      const q = a.defaultQuery;
      if (!q || typeof q !== "object" || Array.isArray(q) || !Object.values(q).every((v) => typeof v === "string")) {
        fail(`${id}.defaultQuery`, "must be an object of string values");
      }
    }

    const auth = a.auth;
    if (typeof auth === "string") {
      if (!["none"].includes(auth)) fail(`${id}.auth`, `unknown built-in flow ${JSON.stringify(auth)}`);
    } else if (auth && typeof auth === "object") {
      if (!AUTH_TYPES.includes(auth.type)) fail(`${id}.auth`, `type must be one of ${AUTH_TYPES.join(", ")}`);
      if (typeof auth.secret !== "string" || !auth.secret) fail(`${id}.auth`, "secret must name a Worker secret");
      if (auth.type === "header" && !auth.header) fail(`${id}.auth`, "header is required for type 'header'");
      if (auth.type === "query" && !auth.param) fail(`${id}.auth`, "param is required for type 'query'");
    } else {
      fail(`${id}.auth`, "required");
    }

    if (!Array.isArray(a.endpoints) || !a.endpoints.length) fail(id, "endpoints must be a non-empty array");
    const endpoints = a.endpoints.map((e: any, i: number) => validateEndpoint(id, e, i));

    if (a.probe) {
      if (typeof a.probe.path !== "string") fail(`${id}.probe`, "path is required");
      if (a.probe.validates && !["credential", "reachability"].includes(a.probe.validates)) {
        fail(`${id}.probe`, 'validates must be "credential" or "reachability"');
      }
    }

    return { ...a, deny: resolveDeny(id, a.deny), endpoints } as ApiManifest;
  });
}
