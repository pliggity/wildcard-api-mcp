#!/usr/bin/env node
/**
 * Checks apis.json before deploying, so a malformed manifest is caught here
 * rather than at the Worker's first request. Runs automatically via `npm run
 * deploy`; run it directly while editing.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "validate-apis-"));
try {
  const bundle = join(dir, "registry.mjs");
  execFileSync("./node_modules/.bin/esbuild", [
    "src/registry.ts", "--bundle", "--format=esm", "--platform=neutral",
    `--outfile=${bundle}`, "--log-level=error",
  ], { stdio: ["ignore", "ignore", "inherit"] });

  const { APIS } = await import(bundle);
  console.log(`apis.json is valid — ${APIS.length} APIs:`);
  for (const a of APIS) {
    console.log(`  ${a.id.padEnd(18)} ${String(a.endpoints.length).padStart(2)} endpoints  ${a.write ? "read+write" : "read-only"}`);
  }
} catch (err) {
  const msg = String(err?.message ?? err);
  console.error(msg.includes("apis.json —") ? msg.split("\n").find((l) => l.includes("apis.json —")) : msg);
  process.exit(1);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
