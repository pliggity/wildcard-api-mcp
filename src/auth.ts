import type { ApiManifest, Env } from "./types";

export interface ResolvedAuth {
  headers: Record<string, string>;
  /** Applied to the request's query string; used by `query`-type auth. */
  query?: Record<string, string>;
  /** Overrides the manifest baseUrl when the credential carries its own host. */
  baseUrl?: string;
}

export class AuthError extends Error {}

/** Reads a manifest-named secret out of the Worker environment. */
function secretValue(env: Env, name: string): string {
  const value = env[name];
  if (typeof value !== "string" || !value) {
    throw new AuthError(
      `Secret ${name} is not set on this Worker. Set it with \`npm run secret -- put ${name}\`.`,
    );
  }
  return value;
}

export async function resolveAuth(api: ApiManifest, env: Env): Promise<ResolvedAuth> {
  if (typeof api.auth === "object") {
    const value = secretValue(env, api.auth.secret);
    switch (api.auth.type) {
      case "bearer":
        return { headers: { authorization: `Bearer ${value}` } };
      case "header":
        return { headers: { [api.auth.header]: `${api.auth.prefix ?? ""}${value}` } };
      case "query":
        return { headers: {}, query: { [api.auth.param]: value } };
      case "basic":
        return { headers: { authorization: `Basic ${btoa(value)}` } };
    }
  }

  switch (api.auth) {
    case "none":
      return { headers: {} };
  }
}

/** Whether a credential is present, without proving it still works. */
export function isConfigured(api: ApiManifest, env: Env): boolean {
  if (typeof api.auth === "object") {
    const value = env[api.auth.secret];
    return typeof value === "string" && value.length > 0;
  }

  switch (api.auth) {
    case "none":
      return true;
  }
}
