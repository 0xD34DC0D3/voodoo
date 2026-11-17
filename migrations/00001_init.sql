-- +goose Up

-- Bearer secrets are never stored in the clear. sessions.id and sessions.ui_id,
-- invites.token, password_resets.token, api_keys.hash, oauth_codes.hash and
-- oauth_tokens.hash all hold sha256 of the secret; the raw value only exists in
-- the cookie, the one-time link, or the client that received it.

-- invite_token records which invite an account came from, so the admin can see
-- every signup an invite produced. Deleting (revoking) the invite clears it.
CREATE TABLE users (
    id            TEXT     PRIMARY KEY,
    email         TEXT     NOT NULL UNIQUE,
    password_hash TEXT     NOT NULL,
    is_admin      BOOLEAN  NOT NULL DEFAULT FALSE,
    disabled_at   DATETIME,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    timezone      TEXT     NOT NULL DEFAULT 'UTC',
    invite_token  TEXT     REFERENCES invites(token) ON DELETE SET NULL
);

CREATE INDEX idx_users_invite_token ON users(invite_token);

-- A session has two cookies. voodoo_session (id) may be set on the parent
-- domain so sibling apps can forward it to /me; it identifies the user and
-- nothing more. The UI cookie (ui_id) is host-only and drives every other
-- cookie route.
CREATE TABLE sessions (
    id           TEXT     PRIMARY KEY,
    user_id      TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at   DATETIME NOT NULL,
    last_used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent   TEXT     NOT NULL DEFAULT '',
    ip           TEXT     NOT NULL DEFAULT '',
    ui_id        TEXT     NOT NULL DEFAULT ''
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE UNIQUE INDEX idx_sessions_ui_id ON sessions(ui_id);

-- Two kinds of invite, told apart by email:
--   email set  -> bound: signup must use that email; single-use (used_at).
--   email NULL -> open: any number of signups until expires_at or deletion;
--                 used_at/used_by record the latest signup.
CREATE TABLE invites (
    token      TEXT     PRIMARY KEY,
    email      TEXT,
    created_by TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    used_at    DATETIME,
    used_by    TEXT     REFERENCES users(id) ON DELETE SET NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE api_keys (
    id           TEXT     PRIMARY KEY,
    user_id      TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash         TEXT     NOT NULL UNIQUE,
    prefix       TEXT     NOT NULL,
    name         TEXT     NOT NULL,
    expires_at   DATETIME,
    last_used_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);

CREATE TABLE password_resets (
    token      TEXT     PRIMARY KEY,
    user_id    TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    used_at    DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);

-- Clients register themselves (RFC 7591 dynamic client registration), so a row
-- here is untrusted input: it means "some software asked for a client_id", not
-- "the operator approved this app". Approval happens per-authorization on the
-- consent screen. All clients are public — no client_secret column — so PKCE is
-- the only proof that the party redeeming a code is the one that started the flow.
--
-- first_approved_by attributes the row to the first user who approved the
-- client: /register is unauthenticated, so this is the honest answer to "whose
-- software is this". NULL for a client that was never approved. Per-user
-- grants live in oauth_tokens. SET NULL, not CASCADE: deleting a user must not
-- delete a client other users may still be using.
CREATE TABLE oauth_clients (
    id            TEXT     PRIMARY KEY,          -- client_id, "vc_…"
    name          TEXT     NOT NULL,             -- client_name, shown on the consent screen
    redirect_uris TEXT     NOT NULL,             -- newline-separated, exact-matched at /authorize
    client_uri    TEXT,                           -- optional homepage, shown on the consent screen
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    first_approved_by TEXT REFERENCES users(id) ON DELETE SET NULL
);

-- Authorization codes. Every field the token request must match is frozen here
-- at authorize time: redirect_uri, resource (RFC 8707 audience), scope, and the
-- PKCE challenge. family is the token family the code will start, so a replayed
-- code can revoke every token minted from it (RFC 6749 §4.1.2).
CREATE TABLE oauth_codes (
    hash           TEXT     PRIMARY KEY,
    client_id      TEXT     NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id        TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT     NOT NULL,
    resource       TEXT     NOT NULL,            -- canonical audience URI
    scope          TEXT     NOT NULL,            -- space-delimited granted scope
    code_challenge TEXT     NOT NULL,            -- S256 only
    expires_at     DATETIME NOT NULL,
    used_at        DATETIME,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    family         TEXT     NOT NULL DEFAULT ''
);

CREATE INDEX idx_oauth_codes_user_id ON oauth_codes(user_id);
CREATE INDEX idx_oauth_codes_expires_at ON oauth_codes(expires_at);

-- Access and refresh tokens share one table: they differ only in kind and
-- lifetime, and every lookup and revocation path wants to treat them alike.
--
-- resource is the token's audience. It is non-negotiable at verification time —
-- /introspect refuses to confirm a token to a resource server other than the one
-- named here, which is what stops a token minted for app A from being replayed
-- against app B.
--
-- family ties a refresh token to its rotation ancestry. Rotation issues a new
-- refresh token and revokes the old one; presenting an already-revoked refresh
-- token means the token leaked, so the whole family is revoked at once.
--
-- granted_at and expires_at are facts about the authorization, not about the row:
-- rotation copies both onto each replacement, so a grant's window is legible from
-- any one of its live tokens and reading the revoked ancestry is never necessary.
-- created_at, by contrast, is when this particular token was minted.
CREATE TABLE oauth_tokens (
    id           TEXT     PRIMARY KEY,
    kind         TEXT     NOT NULL CHECK (kind IN ('access', 'refresh')),
    hash         TEXT     NOT NULL UNIQUE,
    client_id    TEXT     NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id      TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource     TEXT     NOT NULL,
    scope        TEXT     NOT NULL,
    family       TEXT     NOT NULL,
    granted_at   DATETIME NOT NULL,
    expires_at   DATETIME NOT NULL,
    revoked_at   DATETIME,
    last_used_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_oauth_tokens_user_client ON oauth_tokens(user_id, client_id);
CREATE INDEX idx_oauth_tokens_family ON oauth_tokens(family);
-- The hourly sweep deletes by expiry; without this it full-scans the table.
CREATE INDEX idx_oauth_tokens_expires_at ON oauth_tokens(expires_at);

-- +goose Down
DROP TABLE IF EXISTS oauth_tokens;
DROP TABLE IF EXISTS oauth_codes;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS users;
