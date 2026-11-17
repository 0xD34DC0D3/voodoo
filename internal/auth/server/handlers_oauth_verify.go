package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
)

// Token verification (RFC 7662) and revocation (RFC 7009).
//
// Introspection is the one place an access token is ever exchanged for an identity,
// and that is deliberate. Access tokens are not accepted by /me: if they were, a
// token minted for one app would be a working credential at every other app in the
// family, because /me has no way to know who is asking and so no way to check an
// audience. Funnelling verification through a single endpoint that demands the
// caller name itself means the RFC 8707 audience is enforced on every path there is,
// rather than on the ones we remembered.

// touchInterval is how stale last_used_at may get before introspection writes it
// again. Introspection is the busiest OAuth endpoint and SQLite has one writer, so
// the common case must not be a write.
const touchInterval = time.Minute

type introspectResponse struct {
	Active bool `json:"active"`

	// Everything below is present only when Active is true. RFC 7662 §2.2 is explicit
	// that an inactive token's response carries nothing else — a negative answer must
	// not become an oracle for what the token would have been.
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`

	// Voodoo extensions, so a resource server gets the same identity fields /me
	// returns and needs no second call to build its user context.
	Email    string `json:"email,omitempty"`
	IsAdmin  bool   `json:"is_admin,omitempty"`
	Timezone string `json:"timezone,omitempty"`
}

// postIntrospect answers "is this token valid, for me?".
//
// The resource parameter is required, and that is the whole design. An introspection
// endpoint that let the caller omit its own identity would happily confirm any live
// token to anybody holding it, which is exactly the cross-application replay that
// resource indicators exist to prevent.
func (s *Server) postIntrospect(c echo.Context) error {
	ctx := c.Request().Context()
	form, err := bodyParams(c)
	if err != nil {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "malformed form body")
	}

	presented := form.Get("token")
	if presented == "" {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "token is required")
	}
	resource, fail := s.checkResource(form["resource"])
	if fail != nil {
		return oauthErrorBody(c, http.StatusBadRequest, fail)
	}

	inactive := func() error { return c.JSON(http.StatusOK, introspectResponse{Active: false}) }

	tok, err := s.q.GetOAuthTokenByHash(ctx, oauth.HashOf(presented))
	if err != nil {
		return inactive()
	}
	// A refresh token is a credential for the token endpoint, never for a resource
	// server. Confirming one here would let a client that leaked its refresh token have
	// it accepted as an access token.
	if tok.Kind != kindAccess {
		return inactive()
	}
	now := time.Now().UTC()
	if tok.RevokedAt.Valid || !tok.ExpiresAt.After(now) {
		return inactive()
	}
	// The audience check. Same answer as "no such token", because a resource server
	// asking about a token addressed to someone else has no business learning it
	// exists.
	if tok.Resource != resource {
		return inactive()
	}
	u, err := s.q.GetUserByID(ctx, tok.UserID)
	if err != nil || u.DisabledAt.Valid {
		return inactive()
	}

	// Best-effort, and deliberately not fatal: every authorization check above has
	// already passed, so failing the request over a last_used_at write would reject a
	// valid token because of write contention. Same convention as the session and
	// API-key touches in middleware.go.
	if !tok.LastUsedAt.Valid || now.Sub(tok.LastUsedAt.Time) > touchInterval {
		_ = s.q.TouchOAuthToken(ctx, store.TouchOAuthTokenParams{
			LastUsedAt: sql.NullTime{Time: now, Valid: true},
			ID:         tok.ID,
		})
	}

	return c.JSON(http.StatusOK, introspectResponse{
		Active:    true,
		Scope:     tok.Scope,
		ClientID:  tok.ClientID,
		Username:  u.Email,
		TokenType: "Bearer",
		Exp:       tok.ExpiresAt.Unix(),
		Iat:       tok.CreatedAt.Unix(),
		Sub:       u.ID,
		Aud:       tok.Resource,
		Iss:       s.issuer(c),
		Email:     u.Email,
		IsAdmin:   u.IsAdmin,
		Timezone:  u.Timezone,
	})
}

// postRevoke implements RFC 7009. It is unauthenticated because the clients that
// call it are public, and it answers 200 no matter what — including for tokens that
// never existed or belong to someone else — because RFC 7009 §2.2 requires it: a
// distinguishable failure would make this endpoint a way to test whether a token
// string is real.
func (s *Server) postRevoke(c echo.Context) error {
	ctx := c.Request().Context()
	form, err := bodyParams(c)
	if err != nil {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "malformed form body")
	}
	presented, clientID := form.Get("token"), form.Get("client_id")
	if presented == "" {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "token is required")
	}
	if clientID == "" {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "client_id is required")
	}

	tok, err := s.q.GetOAuthTokenByHash(ctx, oauth.HashOf(presented))
	if err != nil || tok.ClientID != clientID {
		return c.NoContent(http.StatusOK)
	}

	now := sql.NullTime{Time: time.Now().UTC(), Valid: true}
	if tok.Kind == kindRefresh {
		// RFC 7009 §2.1: revoking a refresh token SHOULD take the access tokens issued
		// from it with it. The family is exactly that set.
		err = s.q.RevokeOAuthTokenFamily(ctx, store.RevokeOAuthTokenFamilyParams{
			RevokedAt: now,
			Family:    tok.Family,
		})
	} else {
		err = s.q.MarkOAuthTokenRevoked(ctx, store.MarkOAuthTokenRevokedParams{
			RevokedAt: now,
			ID:        tok.ID,
		})
	}
	if err != nil {
		return err
	}
	return c.NoContent(http.StatusOK)
}
