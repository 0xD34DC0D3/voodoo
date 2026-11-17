-- name: CreateUser :one
INSERT INTO users (id, email, password_hash, is_admin, invite_token)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC;

-- name: SetUserAdmin :exec
UPDATE users SET is_admin = ? WHERE id = ?;

-- name: SetUserTimezone :exec
UPDATE users SET timezone = ? WHERE id = ?;

-- name: DisableUser :exec
UPDATE users SET disabled_at = ? WHERE id = ?;

-- name: EnableUser :exec
UPDATE users SET disabled_at = NULL WHERE id = ?;

-- name: CreateSession :one
INSERT INTO sessions (id, ui_id, user_id, expires_at, user_agent, ip)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = ?;

-- name: GetSessionByUIID :one
SELECT * FROM sessions WHERE ui_id = ?;

-- name: TouchSession :exec
UPDATE sessions SET last_used_at = ? WHERE id = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- name: DeleteSessionByUIID :exec
DELETE FROM sessions WHERE ui_id = ?;

-- name: DeleteSessionsByUser :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: GetInviteByToken :one
SELECT * FROM invites WHERE token = ?;

-- name: ListInvites :many
-- signups and signup_emails cover every account created from the invite.
SELECT invites.*,
    (SELECT COUNT(*) FROM users WHERE users.invite_token = invites.token) AS signups,
    CAST(COALESCE((SELECT GROUP_CONCAT(users.email, ', ') FROM users
        WHERE users.invite_token = invites.token), '') AS TEXT) AS signup_emails
FROM invites ORDER BY created_at DESC;

-- name: CreateInvite :one
INSERT INTO invites (token, email, created_by, expires_at)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: DeleteInvite :exec
DELETE FROM invites WHERE token = ?;

-- name: ConsumeInvite :one
-- A bound invite (email set) is consumed once; an open one (email NULL) stays
-- usable until it expires, with used_at/used_by tracking the latest signup.
UPDATE invites
SET used_at = ?, used_by = ?
WHERE token = ? AND expires_at > ? AND (email IS NULL OR used_at IS NULL)
RETURNING token;

-- name: GetPasswordResetByToken :one
SELECT * FROM password_resets WHERE token = ?;

-- name: CreatePasswordReset :one
INSERT INTO password_resets (token, user_id, created_by, expires_at)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: DeletePasswordResetsByUser :exec
DELETE FROM password_resets WHERE user_id = ?;

-- name: ConsumePasswordReset :one
UPDATE password_resets
SET used_at = ?
WHERE token = ? AND used_at IS NULL AND expires_at > ?
RETURNING user_id;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = ? WHERE id = ?;

-- name: CreateApiKey :one
INSERT INTO api_keys (id, user_id, hash, prefix, name, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetApiKeyByHash :one
SELECT * FROM api_keys WHERE hash = ?;

-- name: ListApiKeysByUser :many
SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC;

-- name: DeleteApiKey :exec
DELETE FROM api_keys WHERE id = ? AND user_id = ?;

-- name: DeleteApiKeysByUser :exec
DELETE FROM api_keys WHERE user_id = ?;

-- name: TouchApiKey :exec
UPDATE api_keys SET last_used_at = ? WHERE id = ?;

-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (id, name, redirect_uris, client_uri)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: GetOAuthClient :one
SELECT * FROM oauth_clients WHERE id = ?;

-- The join is LEFT because a client that registered and was never approved has no
-- approver, and that row is exactly the one an operator most wants to see.
-- name: ListOAuthClients :many
SELECT
    c.id,
    c.name,
    c.redirect_uris,
    c.client_uri,
    c.created_at,
    u.email AS first_approved_by_email
FROM oauth_clients c
LEFT JOIN users u ON u.id = c.first_approved_by
ORDER BY c.created_at DESC;

-- ClaimOAuthClientFirstApproval records the first user ever to approve a client.
-- The IS NULL guard makes it first-approver-wins and idempotent, so every later
-- approval, by that user or any other, leaves the attribution alone.
-- name: ClaimOAuthClientFirstApproval :exec
UPDATE oauth_clients
SET first_approved_by = ?
WHERE id = ? AND first_approved_by IS NULL;

-- name: DeleteOAuthClient :execrows
DELETE FROM oauth_clients WHERE id = ?;

-- name: CreateOAuthCode :exec
INSERT INTO oauth_codes (hash, client_id, user_id, redirect_uri, resource, scope, code_challenge, family, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- ConsumeOAuthCode is the atomic single-use gate on the token endpoint: it only
-- matches an unused, unexpired row, so two concurrent redemptions cannot both win.
-- name: ConsumeOAuthCode :one
UPDATE oauth_codes
SET used_at = ?
WHERE hash = ? AND used_at IS NULL AND expires_at > ?
RETURNING client_id, user_id, redirect_uri, resource, scope, code_challenge, family;

-- GetUsedOAuthCodeFamily finds the family of a code that was already redeemed,
-- so a replay can revoke what the first redemption minted.
-- name: GetUsedOAuthCodeFamily :one
SELECT family FROM oauth_codes WHERE hash = ? AND used_at IS NOT NULL;

-- name: DeleteExpiredOAuthCodes :exec
DELETE FROM oauth_codes WHERE expires_at <= ?;

-- name: CreateOAuthToken :exec
INSERT INTO oauth_tokens (id, kind, hash, client_id, user_id, resource, scope, family, granted_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthTokenByHash :one
SELECT * FROM oauth_tokens WHERE hash = ?;

-- name: TouchOAuthToken :exec
UPDATE oauth_tokens SET last_used_at = ? WHERE id = ?;

-- ClaimOAuthToken revokes a token only if it was not already revoked, returning
-- its id when it wins. This is the atomic single-use gate for refresh rotation:
-- two concurrent redemptions of one refresh token both reach this statement, and
-- only the one whose UPDATE matches a still-unrevoked row gets a row back.
-- name: ClaimOAuthToken :one
UPDATE oauth_tokens
SET revoked_at = ?
WHERE id = ? AND revoked_at IS NULL
RETURNING id;

-- name: MarkOAuthTokenRevoked :exec
UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- RevokeOAuthTokenFamily is the refresh-reuse response: one leaked token in a
-- rotation chain invalidates every token descended from the same authorization.
-- name: RevokeOAuthTokenFamily :exec
UPDATE oauth_tokens SET revoked_at = ? WHERE family = ? AND revoked_at IS NULL;

-- ListOAuthGrantsByUser returns the still-usable tokens behind each of a user's
-- grants: at most one access and one refresh per grant, however many generations
-- rotation has been through. Revoked rows are excluded because granted_at rides on
-- every token, so the ancestry rotation leaves behind carries nothing this page needs.
-- name: ListOAuthGrantsByUser :many
SELECT
    t.client_id,
    t.resource,
    t.scope,
    t.granted_at,
    t.expires_at,
    t.last_used_at,
    c.name       AS client_name,
    c.client_uri AS client_uri
FROM oauth_tokens t
JOIN oauth_clients c ON c.id = t.client_id
WHERE t.user_id = ? AND t.revoked_at IS NULL AND t.expires_at > ?
ORDER BY t.granted_at DESC;

-- name: DeleteOAuthTokensByUserClientResource :exec
DELETE FROM oauth_tokens WHERE user_id = ? AND client_id = ? AND resource = ?;

-- Revoking a grant has to take any code that could mint a new one with it: a code
-- issued seconds earlier is still redeemable for a full-lifetime grant, so
-- deleting only tokens leaves the revocation reversible.
-- name: DeleteOAuthCodesByUserClientResource :exec
DELETE FROM oauth_codes WHERE user_id = ? AND client_id = ? AND resource = ?;

-- name: DeleteOAuthCodesByUser :exec
DELETE FROM oauth_codes WHERE user_id = ?;

-- name: DeleteOAuthTokensByUser :exec
DELETE FROM oauth_tokens WHERE user_id = ?;

-- name: DeleteExpiredOAuthTokens :exec
DELETE FROM oauth_tokens WHERE expires_at <= ?;
