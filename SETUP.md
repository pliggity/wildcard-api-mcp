# Setting up your own instance

This deploys a Cloudflare Worker that fronts any REST API as a single MCP server.
You run your own copy — there is no shared instance, and no credential of yours
leaves your Cloudflare account.

## What's automated and what isn't

Everything on the Cloudflare side is automated: KV namespace, generated secrets,
deploy. Two things are not.

**`wrangler login`** — a one-time browser sign-in to your own Cloudflare account.

**An OAuth client at your identity provider** — only if you want the Connect
button (server-side login). Any standard OAuth2/OIDC provider works: Google,
Auth0, GitHub, Okta, your own. Creating the client happens in that provider's
console. If you'd rather skip it, the shared-token mode needs no provider at all.

## Steps

```bash
npm ci
npm run login          # one time, your own Cloudflare account
npm run setup
```

`npm run setup` creates the KV namespace, generates `MCP_TOKEN` and
`KV_ENCRYPTION_KEY`, deploys, and prints your Worker's URL and the new token.
Save the token then: it is shown only once, because Worker secrets can't be
read back. It is safe to re-run: it reuses an existing namespace and leaves
already-set secrets alone.

It then asks for your identity provider's settings (authorize URL, token URL,
client ID and secret, allowed accounts) and prints **your** redirect URI to
register with the provider: `https://<your-worker>.workers.dev/callback`.

### Connect a client

Claude Code:

```bash
claude mcp add --transport http wildcard https://<your-worker>.workers.dev/mcp
claude mcp login wildcard
```

claude.ai / Cowork: **Settings → Connectors → Add → Custom → Web**, give it
`https://<your-worker>.workers.dev/mcp`, and take the detected defaults.

Skipped the identity provider? Connect with the shared token instead, as shown
under "Connecting clients" in the README.

## Adding your own APIs

See the "Adding an API" section of the README. Short version: one entry in
`apis.json`, one `npm run secret -- put NAME`, one `npm run deploy`.

## Optional: 1Password

If you keep credentials in 1Password, add an `opItems` block to `deploy.json` and
`npm run check` will read the shared token from that item's
`MCP_TOKEN` field instead of prompting:

```json
{
  "workerUrl": "https://your-worker.workers.dev",
  "opItems": { "server": "Your item title" }
}
```

Without it, every lookup simply falls back to asking you.
