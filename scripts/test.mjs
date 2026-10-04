#!/usr/bin/env node
/**
 * Bundles test/*.test.ts with the Worker source and runs them under node:test.
 *
 * The Worker imports `cloudflare:workers`, which only exists inside workerd, so
 * it is swapped for a stub here. Everything else runs as it would deployed:
 * the tests drive the real exported handlers with a fake env, KV and fetch.
 */
import { build } from "esbuild";
import { readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";

const OUT = ".test-build";
const entries = readdirSync("test").filter((f) => f.endsWith(".test.ts")).map((f) => `test/${f}`);

rmSync(OUT, { recursive: true, force: true });
await build({
  entryPoints: entries,
  outdir: OUT,
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  outExtension: { ".js": ".mjs" },
  logLevel: "warning",
  plugins: [
    {
      name: "cloudflare-workers-stub",
      setup(b) {
        b.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "stub", namespace: "cf-stub" }));
        b.onLoad({ filter: /.*/, namespace: "cf-stub" }, () => ({
          contents: "export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
        }));
      },
    },
  ],
});

const files = readdirSync(OUT).map((f) => `${OUT}/${f}`);
const { status } = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(status ?? 1);
