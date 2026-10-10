/**
 * Thin wrapper over the 1Password CLI.
 *
 * Uses `op item get --fields label=...` rather than `op read` with an op:// URI,
 * because secret references reject characters that are perfectly legal in a
 * field label — parentheses among them. Field names here are chosen by a human
 * in the 1Password UI, so the lookup has to tolerate whatever they typed.
 *
 * Secrets are read at run time and held only in memory. Every lookup is
 * optional: if `op` is missing or locked, the caller falls back to prompting.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadConfig } from "./config.mjs";

const run = promisify(execFile);

// Optional: set `opItems` in deploy.json to read credentials from 1Password.
// Without it every lookup returns null and callers fall back to prompting.
const items = loadConfig({ required: false }).opItems ?? {};

export const OP_REFS = {
  mcpToken: { item: items.server, field: "MCP_TOKEN" },
};

/** Returns the secret, or null if 1Password can't supply it for any reason. */
export async function opRead(ref, { quiet = false } = {}) {
  const { item, field } = ref;
  if (!item) return null;
  try {
    const { stdout } = await run(
      "op",
      ["item", "get", item, "--fields", `label=${field}`, "--reveal"],
      { encoding: "utf8" },
    );
    return stdout.trim() || null;
  } catch (err) {
    if (!quiet) {
      const reason = /ENOENT/.test(String(err))
        ? "the 1Password CLI (`op`) isn't installed or isn't on PATH"
        : String(err.stderr || err.message).trim().split("\n").pop();
      process.stderr.write(`1Password lookup failed for "${field}" (${reason})\n`);
    }
    return null;
  }
}
