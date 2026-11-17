# Voodoo as an OAuth 2.1 authorization server

Voodoo issues audience-bound OAuth access tokens so that apps in this deployment
can be connected to by AI clients — anything that speaks the Model Context
Protocol's authorization flow, and OAuth clients generally.

This sits *alongside* the session-cookie contract in [auth.md](auth.md), which is
unchanged and remains the right integration for a normal web app. Reach for OAuth
only when the caller is software you did not write and cannot hand a cookie to.

## Why this exists

The cookie contract answers "is this request authenticated?". It cannot answer
"authenticated *for which app?*", because `GET /me` has no way to know who is
asking. That is fine when every caller is an app you wrote on your own domain. It
is not fine once a third-party client holds a long-lived credential: without an
audience, a token minted so one app could be reached would be a working credential
at every other app the same user can reach.

OAuth's resource indicators (RFC 8707) are the fix. The client names the resource
it intends to call, voodoo records that as the token's audience, and verification
refuses to confirm the token to anyone else.

## What is implemented

| Spec | Status |
|---|---|
| RFC 6749 authorization code grant | code + refresh grants only |
| RFC 7636 PKCE | **required**, `S256` only |
| RFC 8707 resource indicators | **required** on `/authorize`, enforced at verification |
| RFC 7591 dynamic client registration | open, rate-limited, public clients only |
| RFC 8414 AS metadata | plus the same document at `/.well-known/openid-configuration` |
| RFC 7662 token introspection | the only way to verify a token |
| RFC 7009 token revocation | refresh revocation takes its family |
| RFC 9207 `iss` in the authorization response | yes |
| OAuth 2.1 refresh rotation | yes, with reuse detection |

Deliberately absent: JWTs and a JWKS endpoint, client secrets, the implicit and
password grants, OpenID Connect ID tokens, and granular scopes.

## Endpoints

```
GET  /.well-known/oauth-authorization-server   discovery (also /openid-configuration)
POST /register                                 dynamic client registration
GET  /authorize    POST /authorize             consent screen and approval
POST /token                                    authorization_code, refresh_token
POST /introspect                               token verification (requires an API key)
POST /revoke                                   client-initiated revocation
```

Users manage what they have approved at `/connections`; admins see every
registered client at `/admin/clients`.

## Voodoo authenticates; apps authorize

A token says which user approved which client for which resource. It does not
say what that user may do there: voodoo has no per-app permissions, and every
active user can approve a client for any resource in the deployment. Your app
decides access from `sub`, using its own rules. `is_admin` is voodoo's own admin
flag, not an app role.

## Which voodoo user is a client connected to?

Clients and grants are owned differently, on purpose:

- **A client is owned by nobody.** `oauth_clients` has no user column, because
  `/register` is unauthenticated and a `client_id` identifies *software*, not a
  person. Several users can hold grants for the same client.
- **A grant is owned by exactly one user.** It is the triple
  `(user_id, client_id, resource)`, listed and revoked per user at `/connections`.
  One user can neither see nor revoke another's.

So the association between a client session and a voodoo user *is* the token, and a
resource server reads it from introspection: `sub` is the voodoo user ID, identical
to what `GET /me` reports. Use it verbatim as your user ID.

For the operator's benefit, `oauth_clients.first_approved_by` additionally records
the first user ever to approve a client, surfaced as "First approved by" on
`/admin/clients` — the closest thing a self-registered client has to an owner. It is
first-approver-wins and never overwritten, since the per-user rows in `oauth_tokens`
already record every authorization; this is attribution for the client row, not a
second copy of who holds access. A blank means the client registered and nobody ever
approved it, so it holds no access at all.

Note the granularity: because a grant is keyed on `(user, client, resource)` and not
per session, two clients sharing one `client_id` against the same resource are a
single revocable unit. Clients that register per installation get their own row.

## Integrating a resource server

Say your app is served at `https://app.<parent-domain>` and its MCP endpoint is
`https://app.<parent-domain>/mcp`. That URL — canonicalized — is your **canonical
resource URI**, and it is the audience of every token minted for you.

### 1. Serve protected-resource metadata

Clients discover where to authenticate from your app, not from voodoo:

```
GET /.well-known/oauth-protected-resource
{
  "resource": "https://app.<parent-domain>/mcp",
  "authorization_servers": ["https://<voodoo-host>"]
}
```

### 2. Challenge unauthenticated requests

Return `401` with a header pointing at that document, so a client that arrives
cold knows how to begin:

```
WWW-Authenticate: Bearer resource_metadata="https://app.<parent-domain>/.well-known/oauth-protected-resource"
```

### 3. Verify bearer tokens by introspection

```sh
curl -X POST https://<voodoo-host>/introspect \
  -H 'Authorization: Bearer ak_…' \
  -d 'token=vat_…' \
  --data-urlencode 'resource=https://app.<parent-domain>/mcp'
```

- Authenticate with a voodoo API key minted at `/keys`. The key identifies the
  *user who minted it*, not your app: voodoo has no app identities. Mint it from a
  non-admin service account. An API key is the **only** accepted credential here —
  a session cookie gets a `401`, so a logged-in browser cannot use this endpoint to
  test token strings.
- **`resource` is required, and it must be your own canonical URI.** This is the
  audience check. Sending someone else's URI, or omitting it, does not get you a
  more permissive answer — omitting it is a `400`.
- `{"active": true, …}` carries `sub`, `email`, `is_admin`, `timezone`: the same
  identity fields `GET /me` returns, so no second call is needed. Use `sub`
  verbatim as your user ID — it is the same value `/me` reports. `is_admin` means
  voodoo admin, not a role in your app.
- `{"active": false}` and nothing else means do not serve the request. It covers
  unknown, expired, revoked, wrong-audience, and disabled-user, deliberately
  without saying which.

Cache positive results briefly (say 60 seconds, keyed by the token) and put a
short timeout on the call, failing closed — the same advice as for `/me`.

### Access tokens are not accepted at `/me`

This is intentional and worth understanding before you try it. `/me` cannot check
an audience, because nothing in the request tells it who is asking. Accepting an
access token there would reintroduce exactly the cross-app replay that resource
indicators exist to prevent, so `/me` takes session cookies and `ak_` API keys
only. Introspection is the single verification path, which is what makes the
audience check unskippable rather than merely available.

## Which resource URIs are valid

Voodoo mints tokens only for audiences inside its own trust boundary, and derives
that boundary from the session-cookie configuration rather than from a second list
to keep in sync:

| Deployment | Valid audiences |
|---|---|
| `VOODOO_COOKIE_DOMAIN` set (the multi-app case) | that parent domain and its subdomains, over `https` |
| `VOODOO_COOKIE_DOMAIN` empty (single host) | voodoo's own origin, from `VOODOO_BASE_URL` |
| `VOODOO_COOKIE_SECURE=false` (local dev) | additionally `http` on `localhost` and loopback |

The multi-app rule is the same one that governs post-login redirects, on purpose —
one answer in voodoo to "which hosts are ours". Anything else is refused with
`invalid_target`, naming the URI that was rejected.

A single-host deployment therefore **must** set `VOODOO_BASE_URL`: without it there
is no origin to compare against and every authorization fails.

Resource URIs are canonicalized before comparison: scheme and host are lowercased
and a default port is dropped, so `https://APP.Example.com:443/mcp` and
`https://app.example.com/mcp` are one audience. A trailing slash on a non-empty
path is **not** folded — `/mcp` and `/mcp/` are different resources — and a
fragment or userinfo component is rejected outright.

## Client registration is open, and that is fine

`/register` is unauthenticated, because a client that has never met this server
needs a `client_id` before it can start a flow. Registering grants nothing:

- No secret is issued. Every client is public and PKCE is what binds a code to
  the software that requested it.
- A registration is just a row. The only capability it confers is rendering a
  self-reported `client_name` on a consent screen the user must still read and
  approve.
- Redirect URIs are exact-matched at `/authorize` — no prefix or origin matching —
  so a client cannot widen its own targets after registering.
- Plaintext `http` redirect targets are confined to loopback — the whole
  `127.0.0.0/8` range, `::1`, and `localhost`, on any port, as RFC 8252 §7.3
  requires for native apps that cannot predict their own listener port.
- Redirect URIs and `client_uri` must be printable ASCII with no userinfo, so
  what the consent screen shows is what the browser visits. Control and format
  characters (bidi overrides, zero-width) are stripped from `client_name`.
  `/authorize` re-checks the stored redirect URI against these rules.
- The endpoint is rate-limited per IP, since it is the only unauthenticated
  endpoint that writes rows.

The consent screen says the name is self-reported, and `/admin/clients` lets the
operator see everything that has ever registered.

## Token lifetimes and revocation

- A database failure at `/token` is a `500` with `server_error`, never
  `invalid_grant`, so a client does not discard a credential that is still good.
- Access tokens live one hour (`VOODOO_OAUTH_ACCESS_TTL_MINUTES`).
- Refresh tokens live 30 days (`VOODOO_OAUTH_REFRESH_TTL_DAYS`) as an **absolute**
  ceiling. Rotation issues a new refresh token but carries the original deadline
  over, so an approval expires when the user was told it would rather than living
  forever through use.
- Authorization codes live one minute, are single-use, and are consumed even when
  the PKCE check then fails. Presenting a used code again revokes every token
  minted from it.
- Refresh rotation includes reuse detection: presenting an already-spent refresh
  token revokes the entire rotation family, including the token the honest client
  is currently holding. Losing a race to spend the same token counts as reuse. That is the intended, drastic outcome — the alternative
  leaves a thief with working access.

A grant dies when the user revokes it at `/connections`, when the client calls
`/revoke`, when an admin deletes the client, disables the account, or revokes the
account's sessions, or when the user's password is reset. The last three go through
one `revokeAllCredentials` helper, so "lock this account out" always means sessions,
API keys, tokens, *and* unredeemed authorization codes — never a subset.

## Scope

One scope exists, `voodoo:identity`, and it is granted by default. Every
authenticated user can already reach every app in this deployment, so finer scopes
would advertise a distinction nothing enforces. A request naming unsupported
scopes alongside it is narrowed to what is supported; a request naming *only*
unsupported scopes is an `invalid_scope` error. The granted scope is always echoed
in the token response.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `VOODOO_BASE_URL` | — | The issuer identifier. Clients compare it against the URL they fetched metadata from. Required (https) when cookies are secure; the fallback to the request's own origin is reachable only in insecure local dev. |
| `VOODOO_OAUTH_ACCESS_TTL_MINUTES` | `60` | Must be positive. |
| `VOODOO_OAUTH_REFRESH_TTL_DAYS` | `30` | Must be positive. Absolute, not sliding. |

The valid-audience rule is derived from `VOODOO_COOKIE_DOMAIN` and
`VOODOO_COOKIE_SECURE`; there is no separate resource allowlist to maintain.

## Storage

Three tables, defined in `migrations/00001_init.sql`: `oauth_clients`,
`oauth_codes`, `oauth_tokens`. `oauth_clients.first_approved_by` attributes a
client to the first user who approved it; `oauth_codes.family` is the token
family a code starts.
Codes and tokens are stored as SHA-256 hashes, so a database read cannot be
replayed as a credential — the same treatment `api_keys` gets. Expired rows are
swept hourly; nothing depends on the sweep for correctness, since every lookup
checks expiry itself.
