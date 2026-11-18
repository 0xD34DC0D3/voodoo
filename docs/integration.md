# Integrating an app with voodoo

Voodoo is the shared login for every app under one parent domain
(`example.com` here, set by `VOODOO_COOKIE_DOMAIN`). The design is
deliberately boring: a session cookie scoped to the parent domain plus one
identity endpoint. A sibling app needs no client registration, shared secret,
OAuth or JWTs — it integrates by reading a cookie and making one HTTP call.
(Voodoo is also an OAuth authorization server, for clients you didn't write;
see [Connecting AI clients](#connecting-ai-clients-oauth).)

## How it works

1. Voodoo sets an opaque session cookie, **`voodoo_session`**, with
   `Domain=.example.com; Path=/; HttpOnly; Secure; SameSite=Lax`. Because it
   is scoped to the parent domain, the browser sends it to every
   `*.example.com` app automatically — logging in once is SSO everywhere.
2. Your app never issues its own session. It forwards the cookie to voodoo's
   `GET /me` server-side and treats the response as the identity. That cookie
   only works at `/me` and `/logout`: voodoo's own pages (keys, admin, OAuth
   consent) need a second, host-only cookie your app never sees.
3. Users who aren't signed in get redirected to voodoo's login page with a
   `next` parameter pointing back at your app.

## The contract

**`GET /me`** — the integration seam. Send the user's cookie (or an API key):

```sh
curl https://auth.example.com/me -H 'Cookie: voodoo_session=<value>'
curl https://auth.example.com/me -H 'Authorization: Bearer ak_…'
```

- `200` with `{"id", "email", "is_admin", "timezone"}` (snake_case) when the
  session or key is valid. Key-authenticated responses also carry
  `"key": {"id", "name"}` (the API key's id and label); cookie-authenticated
  responses have no `key` field.
- `401` with no body otherwise — expired, revoked, disabled user, or missing.
- The session cookie wins if both credentials are present. Each successful
  call touches `last_used_at` on the session or key.

**`GET /login?next=<url-encoded return URL>`** — where to send signed-out
browsers. After login, voodoo 302s the user to `next`. Allowed values: a local
path (`/inbox`), or an absolute `https://` URL on `example.com` or any
subdomain. In local dev (`VOODOO_COOKIE_SECURE=false`), `http(s)://localhost`
on any port is also allowed. Anything else is dropped and the user lands on
voodoo's home page — open redirects are rejected, not errors.

**`POST /logout`** — revokes the session and clears the cookie. Simplest
integration is an HTML form in your app posting directly to
`https://auth.example.com/logout` (the cookie rides along). A server-side
`fetch` with the cookie forwarded also works.

**API keys** (for CLIs and scripts): users mint `ak_…` keys at
`https://auth.example.com/keys` and pass them as
`Authorization: Bearer ak_…` to the same `GET /me`.

## Integration checklist

- Serve your app on a `*.example.com` subdomain (in practice: a Caddy vhost
  on the same server — see [deploy.md](deploy.md)).
- Add an auth middleware: read `voodoo_session`, call `GET /me` with the
  cookie forwarded, put the returned user on the request context.
- On `401`: redirect browsers to
  `https://auth.example.com/login?next=<your full request URL>`; return
  `401` for API/non-GET requests.
- Cache positive `/me` results briefly (60 seconds, keyed by the cookie
  value) so you aren't paying a network hop per request. Don't cache "voodoo
  was unreachable" as signed-out.
- Put a 5-second timeout on the `/me` call and fail closed.
- Use voodoo's `id` verbatim as your app's user identifier.
- No registration on the voodoo side — every authenticated user can reach
  every app.

## Go apps: `voodooauth`

Go apps don't have to write the checklist above themselves. Package
[`voodooauth`](../voodooauth) (`github.com/0xD34DC0D3/voodoo/voodooauth`,
stdlib only) implements it as plain `net/http` middleware: `Middleware` puts
the user on the context, `RequireUser` / `RequireAdmin` enforce, `LoginURL` /
`LogoutURL` feed your templates. Set `AppURL` to your app's external origin so
`next=` never comes from the `Host` header. When voodoo is unreachable,
protected routes answer `503` rather than sending a signed-in user to log in.

## Connecting AI clients (OAuth)

The cookie contract above covers apps you wrote. For software you didn't — an MCP
client, say — voodoo is also a minimal **OAuth 2.1 authorization server**: PKCE,
dynamic client registration, and audience-bound tokens via RFC 8707 resource
indicators, so a token minted for one app is useless at another.

Your app serves protected-resource metadata and verifies bearer tokens with one
call to `POST /introspect`, naming its own canonical URI. Users review and revoke
what they've approved at `https://auth.example.com/connections`.

Full integration guide: [oauth.md](oauth.md).

## Local development

A production cookie is scoped to the parent domain (`.example.com`), so an app on `localhost`
never receives it. Two options:

- Run voodoo locally (see the quickstart in the [README](../README.md#quickstart)). With
  `VOODOO_COOKIE_DOMAIN` empty and `VOODOO_COOKIE_SECURE=false`, the cookie is
  host-only on `localhost` and shared across ports, and `next=` accepts
  localhost URLs — so `localhost:8081` can round-trip through
  `localhost:8080/login` exactly like prod.
- Or add a dev-only bypass flag to your app (e.g. `MYAPP_AUTH_DISABLED=true`)
  and skip auth entirely while hacking.
