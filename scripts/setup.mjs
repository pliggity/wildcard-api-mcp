#!/usr/bin/env node
/**
 * One-time bootstrap: everything that can be automated, then the identity
 * provider's settings for the Connect flow, which only you can create.
 *
 * Safe to re-run — it reuses an existing KV namespace and skips secrets that
 * are already set.
 */
import { execFileSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";

const WRANGLER = "./node_modules/.bin/wrangler";
const rl = createInterface({ input: process.stdin, output: process.stderr });

const say = (s = "") => process.stderr.write(s + "\n");
const run = (args, opts = {}) =>
  execFileSync(WRANGLER, args, { encoding: "utf8", stdio: ["pipe", "pipe", "inherit"], ...opts });

function step(n, title) {
  say(`\n\x1b[1m${n}. ${title}\x1b[0m`);
}

// ---------------------------------------------------------------- preflight
step(1, "Checking Cloudflare login");
try {
  const who = run(["whoami"]);
  const email = who.match(/associated with the email ([^\s.]+@[^\s.]+\.\S+?)\./)?.[1];
  say(`   logged in${email ? ` as ${email}` : ""}`);
} catch {
  say("   Not logged in. Run:  npx wrangler login");
  process.exit(1);
}

// ------------------------------------------------------------------- KV
step(2, "KV namespace (stores OAuth grants and runtime config)");
const cfgPath = "wrangler.jsonc";
let wrangler = readFileSync(cfgPath, "utf8");
const existingId = wrangler.match(/"binding":\s*"OAUTH_KV",\s*"id":\s*"([^"]+)"/)?.[1];

let kvId = existingId;
let reusable = false;
if (existingId) {
  try {
    run(["kv", "key", "list", `--namespace-id=${existingId}`, "--remote"], { stdio: ["pipe", "pipe", "pipe"] });
    reusable = true;
    say(`   reusing existing namespace ${existingId}`);
  } catch {
    say(`   configured namespace ${existingId} is not reachable on this account — creating a new one`);
  }
}
if (!reusable) {
  const out = run(["kv", "namespace", "create", "OAUTH_KV"]);
  kvId = out.match(/"id":\s*"([0-9a-f]{32})"/)?.[1];
  if (!kvId) {
    say("   Could not parse the new namespace id from wrangler output. Create it manually and re-run.");
    process.exit(1);
  }
  wrangler = existingId
    ? wrangler.replace(existingId, kvId)
    : wrangler.replace(/("observability")/, `"kv_namespaces": [\n    { "binding": "OAUTH_KV", "id": "${kvId}" }\n  ],\n  $1`);
  writeFileSync(cfgPath, wrangler);
  say(`   created ${kvId} and wrote it into wrangler.jsonc`);
}

// --------------------------------------------------------------- secrets
const existingSecrets = new Set(
  (() => {
    try {
      return JSON.parse(run(["secret", "list"], { stdio: ["pipe", "pipe", "pipe"] }).match(/\[[\s\S]*\]/)[0]).map((s) => s.name);
    } catch {
      return [];
    }
  })(),
);

function putSecret(name, value) {
  execFileSync(WRANGLER, ["secret", "put", name], { input: value, stdio: ["pipe", "ignore", "inherit"] });
  say(`   set ${name}`);
}

step(3, "Generated secrets");
for (const [name, gen] of [
  ["PERSONAL_MCP_TOKEN", () => randomBytes(24).toString("base64url")],
  ["KV_ENCRYPTION_KEY", () => randomBytes(32).toString("base64")],
]) {
  if (existingSecrets.has(name)) say(`   ${name} already set — leaving it alone`);
  else putSecret(name, gen());
}

// ---------------------------------------------------------------- deploy
step(4, "Deploying");
const deployOut = run(["deploy"]);
const workerUrl = deployOut.match(/(https:\/\/[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev)/i)?.[1];
if (!workerUrl) {
  say("   Deployed, but could not read the URL from wrangler's output.");
  say("   Find it in the Cloudflare dashboard and add it to deploy.json as workerUrl.");
} else {
  say(`   live at ${workerUrl}`);
}

// ----------------------------------------------- identity provider (optional)
step(5, "Identity provider for the Connect button (optional)");
say(`
   Any standard OAuth2/OIDC provider works: Google, Auth0, GitHub, Okta, your own.
   In its console, create a web-application OAuth client with this redirect URI:

      ${workerUrl ?? "https://<your-worker>.workers.dev"}/callback

   Skip this to use only the shared token (PERSONAL_MCP_TOKEN).
`);
const ready = (await rl.question("   Have the provider's endpoints and client credentials? [y/N] ")).trim().toLowerCase();
if (ready === "y") {
  const ask = async (name, prompt) => {
    const value = (await rl.question(`   ${prompt}: `)).trim();
    if (value) putSecret(name, value);
  };
  await ask("OAUTH_AUTHORIZE_URL", "Authorize URL");
  await ask("OAUTH_TOKEN_URL", "Token URL");
  await ask("OAUTH_CLIENT_ID", "Client ID");
  await ask("OAUTH_CLIENT_SECRET", "Client secret");
  await ask("OAUTH_ALLOWED_USERS", "Account(s) allowed to log in, comma-separated (login is refused without this)");
  await ask("OAUTH_SCOPES", "Scopes [openid email]");
  await ask("OAUTH_USERINFO_URL", "Userinfo URL, only if the provider has no OIDC id_token (e.g. GitHub) [none]");
  await ask("OAUTH_USER_CLAIM", "Claim naming the account [email]");
} else {
  say("   Skipped — re-run `npm run setup` any time to add it.");
}

// ----------------------------------------------------------------- record
if (workerUrl) {
  const prev = existsSync("deploy.json") ? JSON.parse(readFileSync("deploy.json", "utf8")) : {};
  writeFileSync("deploy.json", JSON.stringify({ ...prev, workerUrl }, null, 2) + "\n");
  say("\n   wrote deploy.json");
}

step(6, "Connect a client");
say(`
   Claude Code:
     claude mcp add --transport http wildcard ${workerUrl ?? "<worker-url>"}/mcp
     claude mcp login wildcard

   claude.ai / Cowork:
     Settings > Connectors > Add > Custom > Web
     ${workerUrl ?? "<worker-url>"}/mcp
     Take the detected defaults (Always required + register automatically).

   Add API keys for other APIs as you add manifests to apis.json:
     npm run secret -- put SOME_TOKEN
`);
rl.close();
