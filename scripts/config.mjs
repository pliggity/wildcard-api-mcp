/**
 * Per-deployment settings, written by `npm run setup` into deploy.json.
 *
 * Nothing here is secret — it is the Worker's public URL and, optionally, the
 * names of 1Password items to read credentials from. It exists so the scripts
 * work for anyone who clones this repo rather than only for its author.
 */
import { readFileSync } from "node:fs";

const FILE = new URL("../deploy.json", import.meta.url);

export function loadConfig({ required = true } = {}) {
  try {
    return JSON.parse(readFileSync(FILE, "utf8"));
  } catch {
    if (!required) return {};
    console.error(
      "No deploy.json found. Run `npm run setup` first — it deploys the Worker and records its URL.",
    );
    process.exit(1);
  }
}

export function workerUrl(cfg) {
  if (!cfg.workerUrl) {
    console.error("deploy.json has no workerUrl. Re-run `npm run setup`.");
    process.exit(1);
  }
  return cfg.workerUrl.replace(/\/$/, "");
}
