package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"

	kindAccess  = "access"
	kindRefresh = "refresh"
)

// invalidRefreshDesc is one answer for every way a refresh token can fail, so a
// client cannot use the error to learn which tokens ever existed.
const invalidRefreshDesc = "refresh token is invalid, expired, or has been revoked"

var errUserDisabled = errors.New("user is disabled")

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (s *Server) postToken(c echo.Context) error {
	form, err := bodyParams(c)
	if err != nil {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "malformed form body")
	}
	switch form.Get("grant_type") {
	case grantAuthorizationCode:
		return s.tokenFromCode(c, form)
	case grantRefreshToken:
		return s.tokenFromRefresh(c, form)
	case "":
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest, "grant_type is required")
	default:
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeUnsupportedGrantType,
			"supported grant types: "+grantAuthorizationCode+", "+grantRefreshToken)
	}
}

func (s *Server) tokenFromCode(c echo.Context, form url.Values) error {
	ctx := c.Request().Context()
	now := time.Now().UTC()

	clientID, presented := form.Get("client_id"), form.Get("code")
	if clientID == "" || presented == "" {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest,
			"client_id and code are required")
	}

	// Consuming and issuing share one transaction, so a replay that arrives while
	// the first redemption is in flight waits for it and then revokes what it minted.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oauthServerError(c, err)
	}
	defer tx.Rollback()
	qtx := s.q.WithTx(tx)

	// Consuming first is what makes a code single-use under concurrency: the UPDATE
	// matches only an unused, unexpired row, so of two simultaneous redemptions
	// exactly one can win. Every check below then runs against the frozen copy.
	hash := oauth.HashOf(presented)
	row, err := qtx.ConsumeOAuthCode(ctx, store.ConsumeOAuthCodeParams{
		UsedAt:    sql.NullTime{Time: now, Valid: true},
		Hash:      hash,
		ExpiresAt: now,
	})
	if errors.Is(err, sql.ErrNoRows) {
		// A code seen twice was intercepted by someone (RFC 6749 §4.1.2), and we
		// cannot tell which redeemer is honest, so everything it minted dies.
		family, err := qtx.GetUsedOAuthCodeFamily(ctx, hash)
		switch {
		case err == nil:
			if err := revokeFamily(ctx, qtx, family, now); err != nil {
				return oauthServerError(c, err)
			}
			if err := tx.Commit(); err != nil {
				return oauthServerError(c, err)
			}
		case !errors.Is(err, sql.ErrNoRows):
			return oauthServerError(c, err)
		}
		// Unknown, expired, or already redeemed — all one answer, so a client cannot
		// use the error to learn which codes ever existed.
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant,
			"authorization code is invalid, expired, or already used")
	}
	if err != nil {
		return oauthServerError(c, err)
	}

	// A rejected redemption still spends the code, so the burn is committed.
	reject := func(body *oauth.ErrorBody) error {
		if err := tx.Commit(); err != nil {
			return oauthServerError(c, err)
		}
		return oauthErrorBody(c, http.StatusBadRequest, body)
	}
	invalidGrant := func(desc string) error {
		return reject(&oauth.ErrorBody{Code: oauth.ErrCodeInvalidGrant, Description: desc})
	}

	if row.ClientID != clientID {
		return invalidGrant("authorization code was not issued to this client")
	}
	// redirect_uri was in the authorization request, so RFC 6749 §4.1.3 requires it
	// here and requires it to match.
	if form.Get("redirect_uri") != row.RedirectUri {
		return invalidGrant("redirect_uri does not match the authorization request")
	}
	if !oauth.VerifyS256(form.Get("code_verifier"), row.CodeChallenge) {
		return invalidGrant("code_verifier does not match the code_challenge")
	}

	// RFC 8707 §2.2: resource is optional on the token request, but when sent it must
	// not reach beyond what was authorized. Silently ignoring a mismatch would let a
	// client believe it holds a token for one audience while holding one for another.
	if fail := s.checkTokenResource(form, row.Resource); fail != nil {
		return reject(fail)
	}

	if err := s.requireActiveUser(ctx, qtx, row.UserID); err != nil {
		if errors.Is(err, errUserDisabled) {
			return invalidGrant("the user account is unavailable")
		}
		return oauthServerError(c, err)
	}

	return s.issueTokens(c, tx, tokenGrant{
		Now:      now,
		ClientID: row.ClientID,
		UserID:   row.UserID,
		Resource: row.Resource,
		Scope:    row.Scope,
		Family:   row.Family,
		// A fresh authorization starts the absolute clock on the whole family.
		GrantedAt:       now,
		FamilyExpiresAt: now.Add(s.cfg.OAuthRefreshTTL),
	})
}

func (s *Server) tokenFromRefresh(c echo.Context, form url.Values) error {
	ctx := c.Request().Context()
	now := time.Now().UTC()

	clientID, presented := form.Get("client_id"), form.Get("refresh_token")
	if clientID == "" || presented == "" {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidRequest,
			"client_id and refresh_token are required")
	}

	tok, err := s.q.GetOAuthTokenByHash(ctx, oauth.HashOf(presented))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return oauthServerError(c, err)
	}
	if err != nil || tok.Kind != kindRefresh {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant, invalidRefreshDesc)
	}

	// Rotation reuse detection. A refresh token is used exactly once; seeing a revoked
	// one again means two parties hold it, and we cannot tell which is the legitimate
	// client. The safe response is to end the whole rotation family and make the user
	// authorize again.
	if tok.RevokedAt.Valid {
		if err := revokeFamily(ctx, s.q, tok.Family, now); err != nil {
			return oauthServerError(c, err)
		}
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant, invalidRefreshDesc)
	}

	if !tok.ExpiresAt.After(now) || tok.ClientID != clientID {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant, invalidRefreshDesc)
	}
	if fail := s.checkTokenResource(form, tok.Resource); fail != nil {
		return oauthErrorBody(c, http.StatusBadRequest, fail)
	}

	scope, ok := oauth.Narrow(tok.Scope, form.Get("scope"))
	if !ok {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidScope,
			"a refresh may only narrow scope; originally granted: "+tok.Scope)
	}

	if err := s.requireActiveUser(ctx, s.q, tok.UserID); err != nil {
		if errors.Is(err, errUserDisabled) {
			return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant, "the user account is unavailable")
		}
		return oauthServerError(c, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return oauthServerError(c, err)
	}
	defer tx.Rollback()
	qtx := s.q.WithTx(tx)

	// Rotation's single-use gate. Claiming the old token and writing its replacement
	// have to be one atomic step: if they are two, concurrent redemptions of the same
	// refresh token can both read it as unrevoked and both succeed, producing two live
	// chains in one family. ClaimOAuthToken only matches a still-unrevoked row, so
	// exactly one racer gets a row back.
	//
	// Keeping it inside the transaction also means a failure while writing the
	// replacement un-spends the old token, so the client's retry works instead of
	// looking like theft.
	if _, err := qtx.ClaimOAuthToken(ctx, store.ClaimOAuthTokenParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		ID:        tok.ID,
	}); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return oauthServerError(c, err)
		}
		// Lost the race: someone else spent this token between our read and our
		// claim. That is reuse like any other, so the family goes, including the
		// tokens the winner was just issued.
		if err := revokeFamily(ctx, qtx, tok.Family, now); err != nil {
			return oauthServerError(c, err)
		}
		if err := tx.Commit(); err != nil {
			return oauthServerError(c, err)
		}
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant, invalidRefreshDesc)
	}

	return s.issueTokens(c, tx, tokenGrant{
		Now:      now,
		ClientID: tok.ClientID,
		UserID:   tok.UserID,
		Resource: tok.Resource,
		Scope:    scope,
		Family:   tok.Family,
		// Carried over, never extended: rotation keeps a client working without letting
		// an approval outlive the window the user agreed to — or letting the connected
		// apps page report today as the day access was granted.
		GrantedAt:       tok.GrantedAt,
		FamilyExpiresAt: tok.ExpiresAt,
	})
}

type tokenGrant struct {
	// Now is the request's single clock reading, so the stored expiry and the
	// advertised expires_in cannot disagree.
	Now      time.Time
	ClientID string
	UserID   string
	Resource string
	Scope    string
	Family   string
	// GrantedAt and FamilyExpiresAt bound the authorization rather than the token:
	// rotation copies both onto every replacement, so neither moves once the user has
	// approved.
	GrantedAt       time.Time
	FamilyExpiresAt time.Time
}

// issueTokens writes a new access and refresh token into tx, commits it, and
// answers the client. The caller has already spent the code or refresh token in
// the same transaction.
func (s *Server) issueTokens(c echo.Context, tx *sql.Tx, g tokenGrant) error {
	ctx := c.Request().Context()
	qtx := s.q.WithTx(tx)

	// An access token outliving its family would keep working after the authorization
	// it descends from has expired.
	accessExpiry := earliest(g.Now.Add(s.cfg.OAuthAccessTTL), g.FamilyExpiresAt)

	// Clients schedule renewal from expires_in, and a sub-second lifetime is not a
	// schedule — it is a token that dies in flight. Refuse it instead, which for a
	// family on its last second is the honest answer: reauthorize.
	expiresIn := int(accessExpiry.Sub(g.Now).Seconds())
	if expiresIn < 1 {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidGrant,
			"this authorization has expired; the user must approve the app again")
	}

	accessRaw, accessHash := oauth.NewSecret(oauth.AccessTokenPrefix)
	refreshRaw, refreshHash := oauth.NewSecret(oauth.RefreshTokenPrefix)

	for _, t := range []struct {
		kind      string
		hash      string
		expiresAt time.Time
	}{
		{kindAccess, accessHash, accessExpiry},
		{kindRefresh, refreshHash, g.FamilyExpiresAt},
	} {
		if err := qtx.CreateOAuthToken(ctx, store.CreateOAuthTokenParams{
			ID:        ids.NewID(),
			Kind:      t.kind,
			Hash:      t.hash,
			ClientID:  g.ClientID,
			UserID:    g.UserID,
			Resource:  g.Resource,
			Scope:     g.Scope,
			Family:    g.Family,
			GrantedAt: g.GrantedAt,
			ExpiresAt: t.expiresAt,
		}); err != nil {
			return oauthServerError(c, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return oauthServerError(c, err)
	}

	return c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  accessRaw,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshRaw,
		// Always echoed, so a client that asked for more than it got learns so here
		// rather than by guessing (RFC 6749 §3.3).
		Scope: g.Scope,
	})
}

// revokeFamily revokes every live token descended from one authorization.
func revokeFamily(ctx context.Context, q *store.Queries, family string, now time.Time) error {
	return q.RevokeOAuthTokenFamily(ctx, store.RevokeOAuthTokenFamilyParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		Family:    family,
	})
}

// oauthServerError logs err and answers with RFC 6749 server_error. A database
// failure is not the client's fault, and reporting it as invalid_grant would make
// a well-behaved client throw away a credential that is still good.
func oauthServerError(c echo.Context, err error) error {
	c.Set(ctxLogErrKey, err)
	return oauthError(c, http.StatusInternalServerError, oauth.ErrCodeServerError, "internal error; try again")
}

// checkTokenResource enforces RFC 8707 §2.2 on a token request: the resource, if
// present, must be the one the grant was issued for. A malformed value reports
// invalid_request, which tells the client something different from a target this
// server declines to serve.
func (s *Server) checkTokenResource(form url.Values, granted string) *oauth.ErrorBody {
	if len(form["resource"]) == 0 {
		return nil
	}
	canonical, fail := s.checkResource(form["resource"])
	if fail != nil {
		return fail
	}
	if canonical != granted {
		return &oauth.ErrorBody{
			Code:        oauth.ErrCodeInvalidTarget,
			Description: "resource " + canonical + " was not the audience authorized for this grant",
		}
	}
	return nil
}

// requireActiveUser fails when a user has been disabled. Tokens outlive the request
// that made them, so every grant re-checks the account rather than trusting that it
// was fine when the code was issued.
func (s *Server) requireActiveUser(ctx context.Context, q *store.Queries, id string) error {
	u, err := q.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.DisabledAt.Valid {
		return errUserDisabled
	}
	return nil
}
