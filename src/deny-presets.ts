import type { DenyRule } from "./types";

/**
 * Named deny-rule sets, referenced from apis.json as `"deny": "noDelete"`.
 * They live here rather than in the JSON so that lifting a restriction is one
 * edit rather than one per manifest that shares it.
 */
export const DENY_PRESETS: Record<string, DenyRule[]> = {
  /** Read and write, but nothing irreversible. Sensible default for any API. */
  noDelete: [
    {
      method: "DELETE",
      path: "/**",
      reason: "Deletes are disabled on this server. Do it in the app's own UI.",
    },
  ],
};
