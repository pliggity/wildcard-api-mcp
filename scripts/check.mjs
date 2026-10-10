#!/usr/bin/env node
/**
 * Ask the deployed server to test every credential it has.
 *
 * Usage: npm run check
 * Reads MCP_TOKEN from the environment, or prompts for it. The token is
 * never echoed and never written to disk.
 */
import { createInterface } from "node:readline";
import { OP_REFS, opRead } from "./op.mjs";
import { loadConfig, workerUrl } from "./config.mjs";

const URL_BASE = process.env.MCP_URL || workerUrl(loadConfig());

function askHidden(prompt) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    // Swallow the echoed characters so the token never reaches the scrollback.
    rl._writeToOutput = (s) => { if (s.includes(prompt)) rl.output.write(prompt); };
    rl.question(prompt, (answer) => {
      rl.close();
      process.stderr.write("\n");
      resolve(answer.trim());
    });
  });
}

// Environment first (useful in scripts), then 1Password, then ask.
let token = process.env.MCP_TOKEN;
if (!token) {
  process.stderr.write("Reading MCP_TOKEN from 1Password... ");
  token = await opRead(OP_REFS.mcpToken, { quiet: true });
  process.stderr.write(token ? "ok\n" : "not available\n");
}
if (!token) token = await askHidden("MCP_TOKEN: ");
if (!token) {
  console.error("No token available.");
  process.exit(1);
}

const res = await fetch(`${URL_BASE}/mcp`, {
  method: "POST",
  headers: {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    accept: "application/json",
  },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "check_auth", arguments: {} },
  }),
});

const body = await res.text();
if (res.status === 401) {
  console.error("401 Unauthorized — that token doesn't match the MCP_TOKEN secret.");
  process.exit(1);
}
if (!res.ok) {
  console.error(`${res.status} ${res.statusText}\n${body.slice(0, 500)}`);
  process.exit(1);
}

try {
  console.log(JSON.parse(body).result.content[0].text);
} catch {
  console.log(body.slice(0, 1000));
}
