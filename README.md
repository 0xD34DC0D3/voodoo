# voodoo

[![CI](https://github.com/0xD34DC0D3/voodoo/actions/workflows/ci.yml/badge.svg)](https://github.com/0xD34DC0D3/voodoo/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/0xD34DC0D3/voodoo.svg)](https://pkg.go.dev/github.com/0xD34DC0D3/voodoo)

voodoo is a small, self-hosted authentication server for a family of apps that
live under one parent domain (`app.example.com`, `wiki.example.com`, ...). Log
in once at `auth.example.com` and every sibling app knows who you are.

It is one Go binary with an embedded SQLite database and server-rendered pages.

- **Sessions.** A session cookie scoped to the parent domain. Sibling apps
  forward it to `GET /me` and get back `{id, email, is_admin, timezone}`. No
  client registration, shared secrets or JWTs.
- **API keys.** Users mint `ak_...` keys for CLIs and scripts; they work at the
  same `GET /me`.
- **Invites.** Accounts are created only from admin-issued invite links, either
  bound to one email address or open until they expire.
- **Admin.** Web pages to manage users, invites, sessions, password-reset links
  and OAuth clients, plus a small CLI.
- **OAuth 2.1 authorization server** for software you didn't write, such as MCP
  clients: PKCE, dynamic client registration, RFC 8707 audience-bound tokens
  and introspection.

## Who it's for

Someone running a handful of their own apps for a small group of trusted
people (a family, a team, a homelab) who wants one login across all of them
without operating a full identity provider. It is built to be simple to read,
run and back up: a static binary, a SQLite file, systemd and a reverse proxy.

## Non-goals and threat model

- **voodoo authenticates; it does not authorize.** It tells an app who the user
  is. Every signed-in user can reach every app; per-app roles and permissions
  are the app's job. `is_admin` means "may administer voodoo", not an app role.
- **An admin's API key is an admin credential.** Admin routes accept either the
  admin's browser session or their `ak_` key, so treat admin keys like the
  admin password.
- No OpenID Connect, no social login, no SAML, no self-service password reset
  by email (admins issue one-time reset links), no 2FA yet.
- One parent domain per deployment. Cross-domain SSO is out of scope.
- Bearer secrets (sessions, invites, reset links, API keys, OAuth tokens) are
  stored only as SHA-256 digests and passwords as argon2id hashes, but the
  database still deserves to be treated as sensitive.

More detail: [docs/auth.md](docs/auth.md) (design, HTTP surface, security
choices) and [docs/oauth.md](docs/oauth.md).

## Prerequisites

- Go 1.27.4 or newer (see `go.mod`). No cgo; SQLite is pure Go.
- For development: `make tools` installs the pinned `sqlc`, `goose` and
  `govulncheck`.

## Quickstart

Run it locally:

```sh
make build
export VOODOO_DB_PATH=./voodoo.db VOODOO_COOKIE_SECURE=false
./bin/voodoo migrate up
./bin/voodoo admin create-user --email you@example.com --admin   # prompts for the password
./bin/voodoo serve                                               # http://localhost:8080
```

Log in as that admin, then invite other people from `/admin/invites` and send
them the `/signup?invite=...` link it shows (the link is shown only once).

## Configuration

voodoo is configured with environment variables. `.env.example` lists every
variable with local-development defaults; `cp .env.example .env` and the binary
loads it from the working directory (variables already set in the environment
take precedence). [docs/auth.md](docs/auth.md#configuration-env) describes each
variable, and `deploy/voodoo.env.example` is a production template.

## Integrating your apps

- Apps you write: forward the cookie to `GET /me`, redirect signed-out users to
  `/login?next=...`. See [docs/integration.md](docs/integration.md).
- Clients you didn't write (MCP and other OAuth clients): see
  [docs/oauth.md](docs/oauth.md).

## Deployment

[docs/deploy.md](docs/deploy.md) is a reference deployment for a single Ubuntu
VPS behind Caddy: systemd unit, Caddyfile, a gated `make deploy` with a
pre-migration backup and health check, encrypted nightly backups to S3, restore
and rollback. The files it uses are in [`deploy/`](deploy/).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately
as described in [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). The bundled Atkinson Hyperlegible Next and JetBrains Mono fonts are
under the SIL Open Font License 1.1 ([OFL.txt](internal/web/static/fonts/OFL.txt)).
