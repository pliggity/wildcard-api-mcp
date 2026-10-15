# wildcard-api-mcp

One MCP server that fronts any REST API, reachable from Claude Code, Cowork and
claude.ai at the same time. Bring your own APIs — none are bundled.

It exposes **eight tools, permanently** — not one tool per endpoint:

| tool | what it does |
|---|---|
| `list_apis` | what's available, whether writes are on, whether the credential is set |
| `describe_api` | endpoints of one API: paths, query params, body shapes, gotchas |
| `call_api` | make the request; the server attaches credentials |
| `check_auth` | prove each credential still works, to separate 401s from bad requests |
| `get_config` | every API the server knows, enabled or not, with auth type, credential presence and guardrails |
| `set_config` | switch APIs off or back on without a deploy |
| `add_api` | register a new API live, from a manifest, without a deploy |
| `remove_api` | delete an API that was added with `add_api` |

APIs are **data**, not code. Adding one means writing a manifest — in
`apis.json`, or live through `add_api` — no TypeScript, no new tool. Tool count
never changes, so context cost stays flat no matter how many APIs are wired up.

## Setup

You need Node.js 22 or later and a Cloudflare account.

```bash
npm ci
npm run login          # one time, your own Cloudflare account
npm run setup
```

`npm run setup` creates the KV namespace, generates a shared token
(`MCP_TOKEN`) and an encryption key, deploys, and prints your Worker's
URL and the token. The token is shown only that once, because a Worker secret
can't be read back. It is safe to re-run. See [SETUP.md](SETUP.md) for the
optional OAuth login.

At this point the server runs with zero APIs configured. See "Adding an API"
below — every API, including the first one, is added the same way.

## Connecting clients

**Claude Code** — a header works here:

```bash
claude mcp add --transport http wildcard https://<your-worker>.workers.dev/mcp --header "Authorization: Bearer <YOUR_TOKEN>"
```

**Cowork / claude.ai** — the custom connector form has no place to put a header,
so the token goes in the path instead:

```
https://<your-worker>.workers.dev/mcp/<YOUR_TOKEN>
```

Both forms hit the same server and the same constant-time check. The path form
puts the secret in a URL, which is marginally leakier (URLs turn up in logs and
history). To rotate it, run `npm run gen-token`, set the result with
`npm run secret -- put MCP_TOKEN`, and update the connector.

## Adding an API

APIs live in **`apis.json`**. Adding one is an edit to that file and a deploy:

```json
{
  "id": "example",
  "description": "One line: what this API is for.",
  "baseUrl": "https://api.example.com/v1",
  "auth": { "type": "bearer", "secret": "EXAMPLE_TOKEN" },
  "docs": "https://example.com/docs",
  "write": false,
  "probe": { "path": "/ping" },
  "endpoints": [
    {
      "method": "GET",
      "path": "/things",
      "summary": "List things.",
      "query": ["limit", "cursor"],
      "notes": "Any gotcha the model needs: required params, date formats, pagination."
    }
  ]
}
```

Then set the secret the manifest names, and deploy:

```bash
npm run secret -- put EXAMPLE_TOKEN
npm run deploy
```

`npm run deploy` validates `apis.json` first and refuses to deploy a broken one.
Run `npm run validate` on its own while editing.

`example.apis.json` holds ready-made manifests for Google Calendar, Tasks,
Sheets, Drive and Gmail, with deny rules for deletes, sharing and sending.
Copy the entries you want into `apis.json`. They use a plain
`GOOGLE_ACCESS_TOKEN` bearer secret, which Google expires after an hour; for
lasting access, add a token module as described under "Who can use a specific
upstream API."

### Adding an API at runtime

`add_api` takes the same manifest shape as an `apis.json` entry and registers it
immediately, stored in KV alongside the bundled ones. It is deliberately
narrower than editing `apis.json`:

- **Any public host works out of the box.** No allowlist, no redeploy. Hosts
  that are IP literals (any spelling), single-label or local names
  (`localhost`, `*.local`, `*.internal`, `*.lan`…), cloud metadata names, or
  wildcard-DNS services like `nip.io` are always refused. This is a name check,
  not a guarantee: a public name can still be made to resolve privately. Redirects are not
  followed unless `ALLOWED_REDIRECT_HOSTS` lists the target.
- **Optional lock-down.** To restrict `add_api` to hosts you've approved, set
  them from a terminal with `npm run secret -- put ALLOWED_NEW_HOSTS`
  (comma-separated). When set, any other host is refused.
- **https only.**
- **Declarative auth only** — `bearer`, `header`, `query`, `basic` or `"none"`.
  Code-backed auth flows are reserved for bundled APIs.
- **The secret must be named `API_*`** (for example `API_WEATHER_KEY`), so an
  added manifest can't name an unrelated secret and have it sent out. The value
  is never set through MCP: run `npm run secret -- put API_WEATHER_KEY`. Until
  it is set, the API is registered but unusable.
- **One credential, one host, for good.** A secret is bound to the first host
  it's added with, and stays bound after `remove_api`. Reusing it for another
  host is refused; name a new `API_*` secret instead.
- **Bounded.** At most 50 added APIs, each manifest at most 128 KB.

**The tradeoff of leaving `ALLOWED_NEW_HOSTS` unset:** whoever (or whatever)
can call `add_api` can register an API at any public host and then send
requests there with `call_api`. That includes anything a prompt-injected
document or web page might talk the model into. It can't read your secrets:
credentials are set only from a terminal, only `API_*` secrets are usable, and
a secret never moves to a different host. But it *can* send data the model has
seen to a host you didn't pick, and it can bind an unused `API_*` secret that
you set later to its own host. If you'd rather not accept that, set
`ALLOWED_NEW_HOSTS`.

`remove_api` deletes a runtime-added API. Bundled APIs can't be removed that
way; `set_config` with `disable` turns any API off, reversibly. Both settings
live in eventually consistent KV, so they can take up to a minute to apply
everywhere — use them for housekeeping, not as a kill switch. To stop an API
immediately, revoke its credential or deploy.

### Credential types

Four declarative shapes cover most APIs — no code required for any of them:

| `auth` | effect |
|---|---|
| `{ "type": "bearer", "secret": "X" }` | `Authorization: Bearer <X>` |
| `{ "type": "header", "secret": "X", "header": "x-api-key" }` | that header, optional `prefix` |
| `{ "type": "query", "secret": "X", "param": "apikey" }` | appended to the query string |
| `{ "type": "basic", "secret": "X" }` | HTTP Basic; the secret holds `user:password` |
| `"none"` | no credential |

If an API needs something these four don't cover — a credential embedded in a
URL, a signature scheme, a custom header pair — that's the one case that still
needs a few lines of code in `src/auth.ts`, following the existing shapes as a
template.

### Fields worth getting right

- **`probe`** — the cheap read `check_auth` uses to prove the credential works.
  Add `expectStatus` when the natural probe is not a 200.
- **`write`** — must be stated explicitly; `false` means GET only.
- **`deny`** — an inline array of `{ method, path, reason }`, or a named preset
  from `src/deny-presets.ts` if you want to share one rule set across several
  manifests for the same provider.
- **`defaultQuery`** — pins anything the upstream would otherwise choose, such as
  an API version, so a server-side default cannot silently change the response
  shape.
- **`notes`** — the only thing standing between the model and a guessed parameter
  name. Note required params with no default, cheap-vs-expensive response
  formats, silent caps, and date formats.

## Guardrails

Deliberate, and all in one place:

- **Host allowlist.** `call_api` can only reach hosts that appear in a manifest's
  base URL, and only beneath its base path (`/v1` never admits `/v1beta`).
  Dot segments (`..`, `.`, and their `%2e` spellings), protocol-relative paths,
  backslashes, control characters, and `?` or `#` inside `path` are rejected,
  because the URL parser would otherwise rewrite them into a different path
  than the one checked. The final URL is re-checked against the base before the
  request goes out. An MCP tool that accepts an arbitrary URL is an SSRF hole
  and a data-exfiltration path.
- **Redirects are not followed by default.** A 3xx comes back to the model with
  its `Location`, so an open redirect on an allowed host can't carry the
  request, or its credential, somewhere else. When an API really does serve
  from another host (Open Library covers redirect to `archive.org`), list those
  hosts in the `ALLOWED_REDIRECT_HOSTS` var in `wrangler.jsonc`
  (`archive.org,*.us.archive.org`). Then a GET is followed to them over https,
  for at most five hops, and the hops carry no credential.
- **Read-only by default.** A manifest must set `write: true` for anything other
  than GET.
- **Deny rules** block specific method + path globs even on write-enabled APIs —
  the place to put "never delete," "never send," "never grant access" for a
  given provider. A rule is matched against the path as sent and as an
  upstream would route it (percent-decoded, repeated slashes collapsed,
  trailing slash dropped), both before the URL is built and again on the URL
  actually sent, so `/%73end`, `/send/` and `/x/%2e%2e/send` hit the same rule
  as `/send`.
- **Response truncation** at 30k chars by default, 200k ceiling, with the real
  length reported so the caller knows to narrow the query. Bodies are read only
  as far as the cap, so an upstream streaming gigabytes can't exhaust the
  Worker's memory; images over 5 MB are refused without being read in full.
- **Credentials never enter the model's context.** They are Worker secrets,
  attached during the fetch. `call_api` has no token argument.

The deny rules matter beyond typos: API responses are untrusted input, and a
calendar invite or email body can carry text aimed at the model. A deny rule on
send/delete/share endpoints means the worst case of a successful injection is a
bad draft, not a sent message or a granted permission.

## Authentication

Two layers, and they solve different problems — don't conflate them.

**Who can use this server (server-side login).** The Worker is its own OAuth
2.1 authorization server, built on `@cloudflare/workers-oauth-provider`. Clients
(Claude Code, claude.ai) authenticate against *your* server, not against
whatever upstream API they end up calling. Out of the box this federates to
whichever identity provider you wire into `src/oauth.ts` — **any standard
OAuth2/OIDC provider works**: Google, Auth0, GitHub, Okta, your own IdP. The
server only needs, from whichever provider you pick:

- an authorize URL and a token URL,
- a client ID and secret,
- one callback route that exchanges a code for tokens,
- somewhere to persist the result (Workers KV here).

That's the entire interface `src/oauth.ts` expects, and all of it is
configuration: `OAUTH_AUTHORIZE_URL`, `OAUTH_TOKEN_URL`, `OAUTH_CLIENT_ID` and
`OAUTH_CLIENT_SECRET` as Worker secrets, with your Worker's `/callback` as the
redirect URI. `npm run setup` asks for them. Swapping providers means changing
those values, not code. The approval screen, the pending-request bookkeeping in
KV, and the account pin are provider-agnostic.

The pin is `OAUTH_ALLOWED_USERS`, a comma-separated list of accounts, and login
is refused until it is set — otherwise anyone with an account at your provider
could connect. The account is read from the OIDC `id_token` (claim
`OAUTH_USER_CLAIM`, default `email`); for a provider without one, such as
GitHub, set `OAUTH_USERINFO_URL` and the claim to read from it (`login`).
The `id_token` must name your client as its audience, and when the claim is
`email` the provider (`id_token` or userinfo) must say `email_verified: true`. Some providers (Microsoft Entra
among them) leave that flag out and let users edit their email, so with those,
pin a stable id such as `sub` or `oid` instead. The pin is checked again on
every request, not just at login, so removing an account from the list cuts off
the tokens it already holds.
`OAUTH_SCOPES` defaults to `openid email`, and `OAUTH_AUTHORIZE_PARAMS` passes
anything provider-specific through as a query string.

This README deliberately doesn't walk through any one provider's console — that
setup is on each provider's own site and changes independently of this project.

A fallback **shared-token** mode is also always available: a long random
secret accepted as a Bearer header or a trailing path segment, for the case
where you don't want to stand up an OAuth login at all (single user, trusted
network). It short-circuits the OAuth flow entirely. A token shorter than 16
characters is ignored as if unset (`npm run gen-token` makes 32). Prefer the
header: a token in the path ends up in request logs, including Workers
observability.

**Who can use a specific upstream API (per-API credentials).** Independent of
the above. Most APIs use a static key — see "Credential types." Some APIs
(anything requiring per-user delegated access, like a mail or calendar
provider) instead need their own OAuth dance with *that provider*, separate
from your server's login. That dance always happens against whatever service
owns the data — there's no way to route around it by picking a different
identity provider for step one. If you add an API like that, it gets a new
string `auth` value in `src/types.ts` and its own module beside `src/auth.ts`:
fetch and cache an access token, refresh it, and store the refresh token
encrypted in KV with `src/crypto.ts`.

## Credentials at rest

Worker secrets hold every static credential. They are write-only from outside:
their names can be listed, their values cannot be read back, so `wrangler secret
list` is safe to run and to paste.

KV is different — its values *can* be read, by the dashboard, by `wrangler kv key
get`, or by any API token scoped to the namespace. A refresh token that the
Worker has to write to itself (because a Worker cannot write its own secrets)
has nowhere else to live, so it goes in KV encrypted with AES-GCM under a key
held in a Worker secret (`src/crypto.ts`). Reading the KV namespace alone
yields ciphertext.

This does not defend against a compromised Cloudflare account — anyone who can
deploy code can read the secret too. It closes the narrower gap where a
read-only, KV-scoped API token would otherwise yield a live upstream credential
with none of this server's deny rules applying.

## Supply chain

Nothing here reaches npm at run time.

- **No `npx` anywhere.** `npx` fetches from the registry when it can't resolve a
  binary locally, which is how you end up running a package you never chose.
  Every command here goes through `npm run`, which resolves binaries from
  `node_modules/.bin` only.
- **Nothing younger than a week.** `package.json` takes `^` ranges so
  `npm update` can pick up fixes, but `.npmrc` sets `min-release-age=7`, so npm
  only resolves versions that have been public for at least 7 days. A
  compromised or broken release is usually found and pulled within that
  window. This needs npm 11.10 or later; `npm run check-age` verifies the
  lockfile, and CI runs it too.
- **Install with `npm ci`, not `npm install`.** `npm ci` installs precisely what
  `package-lock.json` specifies, with integrity hashes, and fails loudly if the
  lockfile and `package.json` disagree.
- **Install scripts are gated.** From npm 12, dependency install scripts are
  blocked by default and npm names what it skipped; approve them deliberately
  with `npm approve-scripts`. Nothing here needs one: CI installs with
  `--ignore-scripts`.

## Development

```bash
npm run dev          # local server on :8787, secrets from .dev.vars
npm run typecheck
npm test             # adversarial tests of every guardrail
```

`npm test` bundles `test/*.test.ts` with the Worker source and runs it under
`node:test`, driving the real handlers with a fake env, an in-memory KV and a
stubbed `fetch` that records every outbound request. Each test is an attack on
one guardrail (a deny-rule bypass, an escape from the base URL, a borrowed
credential, an oversized response, a forged login) and passes only if nothing
leaves the Worker that shouldn't.

Copy `.dev.vars.example` to `.dev.vars` (gitignored) for local secrets.
Smoke-test a running server:

```bash
curl -s localhost:8787/mcp -H "authorization: Bearer $TOKEN" -H "content-type: application/json" -H "accept: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_apis","arguments":{}}}'
```

`npm run check` asks the deployed server to run `check_auth` against every
credential, using the shared token from the environment, 1Password or a
prompt.

`npm run check-drift` reports manifests whose upstream API description has
changed since they were written. It only looks at manifests with a `spec`
block (`source` is `npm:<package>` with a `packageVersion`, or an https URL
with the `sha256` of the copy you wrote from).

### Build and CI

`npm run build` bundles the Worker into `dist/` without deploying, which
is the quickest way to see that it still builds.

CI runs on every push and pull request: release-age check, `npm ci`,
typecheck, validation of both `apis.json` and `example.apis.json`, the
bundle build, the tests when present, and an audit of runtime
dependencies. It never deploys.

### What the validator checks

Ids are unique and well-formed, `baseUrl` parses and has no trailing slash,
query, fragment or embedded credentials (and is https whenever auth sends a
credential), endpoint fields have the right types,
`write` is explicit, auth types carry their required fields, deny presets
exist, methods are uppercase and real, and every endpoint has a path and
summary. Errors name the API and field.
