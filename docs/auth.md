# Voodoo Auth

How the auth server works today: sessions, API keys, admin, and the HTTP surface. The OAuth authorization server is covered in [oauth.md](oauth.md); deployment in [deploy.md](deploy.md).

## Scope

A user signs up via invite, logs in once and is signed in to every app under the deployment's parent domain, mints API keys for CLIs, and (as admin) manages users, invites, password resets and OAuth clients.

**Non-goals:** cross-domain handoff, audit log table (admin and auth events go to the structured log only), self-service password reset via email (admin-issued reset links exist), OpenID Connect (no ID tokens), scopes on API keys, account self-deletion, impersonation.

## Why this shape

Voodoo serves a small set of apps owned by one developer and used by a small set of trusted people. For those apps the integration is a session cookie scoped to the parent domain plus opaque API keys for CLIs: SSO across every sibling app, trivial revocation, one HTTP call to integrate.

OAuth exists for software the developer did not write, such as MCP clients: voodoo is a minimal OAuth 2.1 authorization server (PKCE, dynamic client registration, RFC 8707 audience-bound opaque tokens, introspection). Sibling apps do not need it. See [oauth.md](oauth.md).

## Repository layout

Single Go module, one binary:

```
voodoo/
├── cmd/
│   └── voodoo/                 # binary: auth server + admin subcommands
│       └── main.go
├── internal/
│   ├── auth/
│   │   ├── server/             # echo handlers, routes, middleware
│   │   ├── views/              # html/template files + render helpers
│   │   ├── store/              # sqlc-generated code + hand-written queries
│   │   ├── password/           # argon2id wrap
│   │   ├── apikey/             # generate / hash / parse ak_ tokens
│   │   ├── oauth/              # OAuth 2.1 helpers (PKCE, tokens, client metadata)
│   │   ├── session/            # cookie helpers
│   │   └── config/             # env → Config struct
│   ├── web/                    # layout, embedded /static assets
│   └── ids/                    # ID generation
├── migrations/                 # goose, embedded in the binary
├── deploy/                     # systemd unit, Caddyfile, deploy and backup scripts
├── docs/                       # this file lives here
├── sqlc.yaml
├── go.mod
└── README.md
```

## Tech, locked

Echo · goose · sqlc · `modernc.org/sqlite` (pure Go) · `golang.org/x/crypto/argon2` · stdlib `html/template`, server-rendered. One small script, `/static/copy-key.js`, adds a Copy button on the new-key page; pages work without it. No inline script (the CSP forbids it), no JS build step, no template codegen.

## Data model

Goose migrations in `migrations/`, embedded in the binary. The auth tables are below. OAuth adds `oauth_clients`, `oauth_codes` and `oauth_tokens` (`migrations/00001_init.sql`).

```sql
users(
  id PK,
  email UNIQUE,
  password_hash,        -- argon2id
  is_admin BOOL,
  disabled_at NULL,
  invite_token NULL FK, -- invite the account signed up with; NULL once it is deleted
  created_at, updated_at
)

sessions(
  id PK,                -- sha256 of the voodoo_session cookie; the raw 32 random bytes never land here
  ui_id UNIQUE,         -- sha256 of the host-only UI cookie (independent secret)
  user_id FK,
  expires_at, last_used_at, created_at,
  user_agent, ip
)

invites(
  token PK,             -- sha256 of the random link token
  email NULL,           -- set: bound, single-use; NULL: open, multi-use until expiry
  created_by FK,
  expires_at,
  used_at NULL, used_by NULL,  -- bound: the one signup; open: the latest
  created_at
)

password_resets(
  token PK,             -- random, single-use
  user_id FK,           -- account being reset
  created_by FK,        -- admin who issued the link
  expires_at, used_at NULL, created_at
)

api_keys(
  id PK,
  user_id FK,
  hash UNIQUE,          -- sha256(raw_key)
  prefix,               -- first 12 chars of raw key, for display
  name,
  expires_at NULL, last_used_at NULL, created_at
)
```

### Storage notes

- **Passwords:** Argon2id, t=1, m=64 MiB, p=4 (~100 ms on a typical VPS).
- **API keys:** SHA-256, no Argon2id needed — keys are 32 random bytes (high entropy). The 12-char prefix is shown in the UI so users can identify a key without revealing it.
- **Session IDs:** SHA-256, same reasoning as API keys. Each cookie carries its raw token; `sessions.id` and `sessions.ui_id` hold only digests. This was plaintext through v1 on the theory that a compromised DB is game over anyway — but that is not quite right. Read access to the DB file (a backup, a stray copy, a bug that dumps a row) is much easier to come by than write access, and a plaintext session ID is directly replayable as a cookie against every site that federates auth here, with no password and no second factor. A digest makes that read useless.
- **Invite and reset tokens:** SHA-256, same reasoning. The link carries the raw token and is shown once at creation; it is not recoverable from the admin listing afterwards.

## HTTP surface

```
Public
  GET  /healthz
  GET  /static/*         (stylesheet, fonts, favicon, copy-key.js)
  GET  /login            POST /login         (POST rate-limited per IP)
  POST /logout
  GET  /signup           POST /signup        (requires ?invite=<token>; POST rate-limited)
  GET  /reset            POST /reset         (requires ?token=<token>; POST rate-limited)

RequireIdentity (either session cookie OR ak_ bearer)
  GET  /me               → JSON {id, email, is_admin, timezone}

RequireUser (UI cookie OR ak_ bearer)
  GET  /                 POST /settings/timezone
  GET  /keys             POST /keys/:id/delete
  GET  /connections      POST /connections/revoke

RequireSession (UI cookie only)
  POST /keys             (mints an API key; an ak_ bearer cannot mint keys)
  GET  /authorize        POST /authorize   (OAuth consent)

OAuth machine endpoints (see oauth.md; all no-store except discovery)
  GET  /.well-known/oauth-authorization-server
  GET  /.well-known/openid-configuration   (same document)
  POST /register         (dynamic client registration; rate-limited per IP)
  POST /token            (rate-limited per IP)
  POST /introspect       (ak_ bearer only)
  POST /revoke

RequireAdmin (UI cookie OR ak_ bearer, plus is_admin)
  GET  /admin
  GET  /admin/users      POST /admin/users/:id/disable
                         POST /admin/users/:id/enable
                         POST /admin/users/:id/sessions/revoke
                         POST /admin/users/:id/promote | demote
                         POST /admin/users/:id/reset    (mints a reset link)
                         (every /admin/users/:id action is 404 for an unknown id)
  GET  /admin/invites    POST /admin/invites
                         POST /admin/invites/:token/delete
  GET  /admin/clients    POST /admin/clients/:id/delete
```

### Cookies

Login sets two cookies for one `sessions` row, each with its own random 32-byte secret. Both are `HttpOnly`, `Secure` (prod), `SameSite=Lax`, `Path=/`, expiry tied to `sessions.expires_at`.

- `voodoo_session` — `Domain` set to the deployment's parent domain (`VOODOO_COOKIE_DOMAIN`). Every sibling host receives it. It proves identity and nothing else.
- UI cookie — `__Host-voodoo_ui` (`voodoo_ui` when `VOODOO_COOKIE_SECURE=false`, where the prefix is not allowed). Host-only (no `Domain`), so sibling hosts never receive it, and the `__Host-` prefix stops them from setting or shadowing it.

Every cookie-authenticated route except `/me` and `/logout` takes the UI cookie only. A `voodoo_session` value presented elsewhere is ignored, so a request carrying only it is treated as signed out.

**What a sibling app gets:** forward `voodoo_session` to `GET /me` for `{id, email, is_admin, timezone}`, and post a logout form to `/logout`.

**What a sibling app cannot do with it** (nor a script injected into one): read or change voodoo's pages, list or mint API keys, revoke connections, use admin pages, or approve an OAuth client. Those take the UI cookie, which never leaves voodoo's host. Cross-origin posts are rejected anyway (below); the split also covers a sibling server or XSS that replays the cookie value directly.

`serve` refuses to start with `VOODOO_COOKIE_DOMAIN` set and `VOODOO_COOKIE_SECURE` off: a shared cookie must not travel over plain HTTP.

`voodoo_flash` carries a one-shot notice across a redirect. It is host-only (no `Domain`), `HttpOnly`, `SameSite=Lax`, 30 s.

### Cross-origin requests (CSRF)

Every unsafe method (POST etc.) goes through Go's `http.CrossOriginProtection`: a browser request whose `Sec-Fetch-Site` (or, failing that, `Origin`) shows another origin gets 403. Requests without either header — CLIs, servers, API-key callers — pass; they carry no ambient cookie. The OAuth machine endpoints `/token`, `/register`, `/introspect`, `/revoke` are exempt: clients call them cross-origin by design and authenticate without a cookie.

One carve-out: `POST /logout` also accepts a post whose `Origin` is an `https://` host on the cookie's parent domain (`VOODOO_COOKIE_DOMAIN`), or `localhost` in insecure local dev, so a sibling app's logout form keeps working. A post from any other site is still rejected. The carve-out is safe because logout only ever ends a session: either cookie identifies the row, and the response deletes it and clears both cookies.

### Response headers

Every response carries `Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'` (own assets only, no inline script or style, no framing), `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`. There is deliberately no `form-action`: approving OAuth consent redirects to the client's redirect URI, which it would block.

### `/me` contract

The integration seam every downstream app calls.

- Accepts `voodoo_session` (or the UI cookie) OR `Authorization: Bearer ak_…`. A cookie wins if both are sent.
- Returns 200 with `{id, email, is_admin, timezone}` on success.
- Returns 401 otherwise — no body.
- Touches `last_used_at` on the session or API key row.

### Authentication, not per-app authorization

Voodoo says who a user is. It does not say what they may do in a given app, and it
has no per-app permissions: every active user can reach every app in the
deployment. Each app decides access itself.

- `is_admin` means "may administer voodoo". It is not an app role. An app that
  needs admins of its own keeps its own list.
- An API key (`ak_…`) identifies the user who minted it, not an app. A relying app
  holding a key acts as that user, including at `/introspect`. Mint app keys from a
  non-admin service account.

## CLI

All subcommands of one binary, sharing config + DB code.

```
voodoo serve
voodoo migrate up | down | status
voodoo admin create-user [--email E] [--admin]   (prompts for the password)
voodoo admin promote <email>
voodoo admin demote  <email>
voodoo admin list
```

Raw SQL via `sqlite3` stays the always-works fallback for admin work.

## Configuration (env)

| Variable | Default | Notes |
|---|---|---|
| `VOODOO_DB_PATH` | — | Path to SQLite file. |
| `VOODOO_PORT` | `8080` | |
| `VOODOO_BIND` | `127.0.0.1` | Interface to bind. Loopback by default since the reverse proxy is the only intended client. Set empty to listen on all interfaces. |
| `VOODOO_BASE_URL` | — | Auth server's public URL. Used for redirects, invite and reset links, and the OAuth issuer. `serve` refuses to start unless it is an `https://` URL while `VOODOO_COOKIE_SECURE` is on. |
| `VOODOO_COOKIE_DOMAIN` | — | Parent domain in prod (e.g. `.example.com`). Leave empty in local dev — host-only cookie on `localhost` is shared across ports. `serve` refuses to start with it set while `VOODOO_COOKIE_SECURE` is off. |
| `VOODOO_COOKIE_SECURE` | `true` | Set `false` in local dev (no HTTPS on `localhost`). |
| `VOODOO_SESSION_TTL_DAYS` | `30` | |
| `VOODOO_OAUTH_ACCESS_TTL_MINUTES` | `60` | OAuth access token lifetime. Must be positive. |
| `VOODOO_OAUTH_REFRESH_TTL_DAYS` | `30` | Absolute ceiling on an OAuth approval; rotation does not extend it. Must be positive. |
| `VOODOO_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. `serve` refuses to start on any other value. |

The binary loads a `.env` file from the working directory if one exists (`godotenv`, best effort). Variables already set in the environment win.

## Security choices (recorded)

- Argon2id with the parameters above. One argon2 call runs at a time; a request that waits more than 5s for its turn gets 503.
- Passwords are at least 15 characters at signup, reset and `voodoo admin create-user`. No composition rules.
- `POST /login`, `/signup` and `/reset` share a per-IP token bucket (burst 10, then one per 6s; IPv6 keyed on its /64); over it is 429. The client IP is `X-Forwarded-For` only when the peer is loopback (the local reverse proxy), otherwise the socket address.
- OAuth has its own per-IP buckets: `POST /register` burst 5 then one per minute, `POST /token` burst 30 then one per 2s.
- Request bodies are capped at 64 KB. The HTTP server sets read-header (5s), read (10s), write (30s) and idle (60s) timeouts.
- API keys are random 32 bytes, SHA-256 stored, shown to the user exactly once.
- Every response that shows a freshly minted API key, reset link or invite link is sent with `Cache-Control: no-store`.
- Sessions are two random 32-byte secrets (parent-domain and UI cookie), one row; revocation = `DELETE FROM sessions`. `POST /logout` with either cookie deletes the row and clears both.
- Invites expire (default 7 days, max 365), belong to their creator, and come in two kinds, chosen by whether the admin enters an email:
  - **Email-bound** (email set): signs up only that address, compared after the same normalisation as user emails (trimmed, lower-cased). The signup form shows it read-only and the server rejects any other email whatever the form sends. Single-use.
  - **Open** (email blank): anyone with the link can sign up, any number of times, until it expires or is deleted. There is no use cap; expiry is the bound.
  - Every account records the invite it came from (`users.invite_token`); `/admin/invites` shows each invite's kind, status, expiry and signups. Deleting an invite revokes the link and clears that record (the accounts stay).
  - An open link is a bearer credential: whoever holds it can create accounts. Send it privately, keep the expiry short, and delete it once the people it was meant for have signed up. Prefer email-bound invites when you know who is joining.
- Disabled users: `disabled_at IS NOT NULL` causes `RequireUser` to 401. An admin can re-enable a user from `/admin/users`; credentials deleted on disable stay deleted.
- Disable, admin session revoke, and a completed password reset all delete every credential the user holds: sessions, API keys, OAuth tokens and unredeemed authorization codes. A user re-mints API keys after logging back in.
- Password reset is **admin-issued, no email**: an admin mints a single-use link from `/admin/users` and hands it to the user out-of-band (same model as invites). Links expire fast (1 hour), reissuing invalidates any prior unused link, completing a reset revokes all of the user's credentials (see above), and the token is consumed atomically so a link works exactly once. Self-service reset via email remains deferred (see below).
- HTTPS-only cookie in prod (`VOODOO_COOKIE_SECURE=true`).

## Deferred (post-v1)

- Cross-domain handoff endpoint (additive; ~100 lines when needed).
- Self-service password reset via email (admin-issued reset links ship today; email would let users recover without an admin).
- 2FA / WebAuthn.
- API key scopes.
- Audit log of admin actions.
- Per-app permissions (today, every authenticated user can access every app).
