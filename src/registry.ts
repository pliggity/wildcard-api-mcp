import rawManifests from "../apis.json";
import type { ApiManifest } from "./types";
import { validateManifests } from "./validate";

/**
 * Every API this server can reach, defined as data in apis.json.
 *
 * Adding one means editing that file and deploying — no code. The JSON is
 * checked by validateManifests at module load, so a malformed manifest fails
 * loudly at startup with the API and field named, rather than surfacing as a
 * confusing request failure later.
 */
export const APIS: ApiManifest[] = validateManifests(rawManifests);

export function getApi(id: string): ApiManifest | undefined {
  return APIS.find((a) => a.id === id);
}

/** Hosts any request is allowed to reach, derived from the manifests themselves. */
export function allowedHosts(): Set<string> {
  return new Set(APIS.map((a) => new URL(a.baseUrl).host));
}
