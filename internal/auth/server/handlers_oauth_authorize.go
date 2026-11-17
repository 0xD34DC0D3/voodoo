package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

// maxStateLen bounds the state parameter we echo back. state is opaque to us and
// ends up in a Location header, so it needs a ceiling; no real client comes close.
const maxStateLen = 512

// authzParams is a validated authorization request. Every field has already passed
// policy, and the values stored on the resulting code come from here — never from
// the raw request a second time.
type authzParams struct {
	ClientID    string
	ClientName  string
	ClientURI   string
	RedirectURI string
	State       string
	Scope       string // granted, not requested
	Challenge   string
	Resource    string // canonical audience
}

// authzError is a rejected authorization request.
//
// An empty RedirectURI carries real meaning: it says the request failed before we
// could establish that the redirect target belongs to the client, so the failure
// must be rendered as a page. Reporting an error to an unverified redirect_uri would
// turn /authorize into an open redirector.
type authzError struct {
	RedirectURI string
	State       string
	Code        string
	Desc        string
}

type authorizeErrorView struct {
	web.Chrome
	Code string
	Desc string
}

type authorizeView struct {
	web.Chrome
	ClientName string
	ClientURI  string
	Resource   string
	Scopes     []string
	UserEmail  string
	Expiry     string
	// RedirectHost is the host the authorization code will actually be delivered to,
	// shown because it is the only field on this page an attacker cannot choose
	// freely: client_name and client_uri are self-reported, and the resource can name
	// a legitimate app while the code goes somewhere else entirely.
	RedirectHost string
	// The rest are echoed into hidden fields so the consent POST can reconstruct the
	// request. They are re-validated from scratch on submit — nothing here is trusted
	// just because it round-tripped through the form.
	ClientID    string
	RedirectURI string
	State       string
	Scope       string
	Challenge   string
	CSRF        string
}

func (s *Server) writeAuthzError(c echo.Context, e *authzError) error {
	if e.RedirectURI == "" {
		return s.render(c, http.StatusBadRequest, "authorize_error.html", authorizeErrorView{
			Chrome: s.pageChrome(c, "authorization error"),
			Code:   e.Code,
			Desc:   e.Desc,
		})
	}
	q := url.Values{"error": {e.Code}}
	if e.Desc != "" {
		q.Set("error_description", e.Desc)
	}
	if e.State != "" {
		q.Set("state", e.State)
	}
	q.Set("iss", s.issuer(c))
	return c.Redirect(http.StatusFound, appendQuery(e.RedirectURI, q))
}

// parseAuthz validates an authorization request. The order is load-bearing: client
// and redirect_uri are settled first, because until both are known good there is
// nowhere safe to send an error.
func (s *Server) parseAuthz(c echo.Context, v url.Values) (authzParams, *authzError) {
	var p authzParams

	// RFC 6749 §3.1: no parameter may appear twice. For these two it matters most,
	// because they decide where an error may be sent.
	for _, k := range []string{"client_id", "redirect_uri"} {
		if len(v[k]) > 1 {
			return p, &authzError{Code: oauth.ErrCodeInvalidRequest, Desc: k + " was sent more than once"}
		}
	}

	clientID := v.Get("client_id")
	if clientID == "" {
		return p, &authzError{Code: oauth.ErrCodeInvalidRequest, Desc: "client_id is required"}
	}
	cl, err := s.q.GetOAuthClient(c.Request().Context(), clientID)
	if err != nil {
		return p, &authzError{Code: oauth.ErrCodeInvalidClient, Desc: "unknown client_id"}
	}

	redirectURI := v.Get("redirect_uri")
	if redirectURI == "" {
		return p, &authzError{Code: oauth.ErrCodeInvalidRequest, Desc: "redirect_uri is required"}
	}
	if !oauth.RedirectURIAllowed(oauth.DecodeRedirectURIs(cl.RedirectUris), redirectURI) {
		return p, &authzError{
			Code: oauth.ErrCodeInvalidRequest,
			Desc: "redirect_uri does not exactly match one registered by this client",
		}
	}
	// Re-checked against current policy, so a row stored under older or looser
	// rules cannot be redirected to.
	if oauth.ValidateRedirectURI(redirectURI) != nil {
		return p, &authzError{Code: oauth.ErrCodeInvalidRequest, Desc: "this client's redirect_uri is not allowed"}
	}
	clientURI := cl.ClientUri.String
	if oauth.ValidateClientURI(clientURI) != nil {
		clientURI = ""
	}

	// Past this point the redirect target is trusted, so failures travel back to the
	// client the way the spec expects.
	state := v.Get("state")
	if len(state) > maxStateLen {
		return p, &authzError{RedirectURI: redirectURI, Code: oauth.ErrCodeInvalidRequest, Desc: "state is too long"}
	}
	fail := func(code, desc string) *authzError {
		return &authzError{RedirectURI: redirectURI, State: state, Code: code, Desc: desc}
	}

	if v.Get("response_type") != responseTypeCode {
		return p, fail("unsupported_response_type", "only the authorization code flow is supported")
	}

	// PKCE is mandatory, not negotiated. Every client here is public, so without a
	// challenge there is nothing tying a code to the software that asked for it — an
	// attacker who intercepts the redirect could simply redeem it.
	if m := v.Get("code_challenge_method"); m != oauth.MethodS256 {
		desc := "code_challenge_method must be S256"
		if m == "" {
			desc = "PKCE is required: send code_challenge and code_challenge_method=S256"
		}
		return p, fail(oauth.ErrCodeInvalidRequest, desc)
	}
	challenge := v.Get("code_challenge")
	if !oauth.ValidChallenge(challenge) {
		return p, fail(oauth.ErrCodeInvalidRequest, "code_challenge is not a valid S256 challenge")
	}

	resource, resourceFail := s.checkResource(v["resource"])
	if resourceFail != nil {
		return p, fail(resourceFail.Code, resourceFail.Description)
	}

	scope, ok := oauth.Grant(v.Get("scope"))
	if !ok {
		return p, fail(oauth.ErrCodeInvalidScope,
			"supported scopes: "+strings.Join(oauth.SupportedScopes(), " "))
	}

	return authzParams{
		ClientID:    cl.ID,
		ClientName:  cl.Name,
		ClientURI:   clientURI,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       scope,
		Challenge:   challenge,
		Resource:    resource,
	}, nil
}

func (s *Server) getAuthorize(c echo.Context) error {
	u, sid, ok := s.consentActor(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}

	p, fail := s.parseAuthz(c, c.QueryParams())
	if fail != nil {
		return s.writeAuthzError(c, fail)
	}

	return s.render(c, http.StatusOK, "authorize.html", authorizeView{
		Chrome:       s.pageChrome(c, "authorize"),
		ClientName:   p.ClientName,
		ClientURI:    p.ClientURI,
		Resource:     p.Resource,
		Scopes:       oauth.ScopeDescriptions(p.Scope),
		UserEmail:    u.Email,
		Expiry:       humanDuration(s.cfg.OAuthRefreshTTL),
		RedirectHost: redirectHost(p.RedirectURI),
		ClientID:     p.ClientID,
		RedirectURI:  p.RedirectURI,
		State:        p.State,
		Scope:        p.Scope,
		Challenge:    p.Challenge,
		CSRF:         consentToken(sid, p),
	})
}

func (s *Server) postAuthorize(c echo.Context) error {
	u, sid, ok := s.consentActor(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}

	form, err := bodyParams(c)
	if err != nil {
		return s.writeAuthzError(c, &authzError{Code: oauth.ErrCodeInvalidRequest, Desc: "malformed form body"})
	}
	// Validate the request before checking the consent token, because the token is
	// bound to the validated request. parseAuthz only reads, so nothing is minted on
	// this path before the token has been verified below.
	p, fail := s.parseAuthz(c, form)
	if fail != nil {
		return s.writeAuthzError(c, fail)
	}

	// The session cookie is SameSite=Lax, so a cross-site POST arrives without it and
	// never reaches this handler authenticated. This token is the second lock: it is
	// derived from the session ID, which is HttpOnly, so only a page voodoo itself
	// served can produce a value that verifies — and because the request is mixed into
	// the hash, it verifies only for the request the user saw.
	if !verifyConsentToken(sid, p, form.Get("csrf")) {
		return s.writeAuthzError(c, &authzError{
			Code: oauth.ErrCodeInvalidRequest,
			Desc: "this approval form is stale or was not issued for this request — start the authorization again",
		})
	}

	if form.Get("decision") != "approve" {
		return s.writeAuthzError(c, &authzError{
			RedirectURI: p.RedirectURI,
			State:       p.State,
			Code:        oauth.ErrCodeAccessDenied,
			Desc:        "the user declined this request",
		})
	}

	// One transaction, because the attribution is part of the approval rather than a
	// side effect of it: a code without its claim leaves the operator looking at a
	// client nobody appears to have approved, and a claim without a code names
	// someone whose approval never took.
	ctx := c.Request().Context()
	raw, hash := oauth.NewSecret(oauth.CodePrefix)
	if err := s.inTx(ctx, func(q *store.Queries) error {
		if err := q.CreateOAuthCode(ctx, store.CreateOAuthCodeParams{
			Hash:          hash,
			ClientID:      p.ClientID,
			UserID:        u.ID,
			RedirectUri:   p.RedirectURI,
			Resource:      p.Resource,
			Scope:         p.Scope,
			CodeChallenge: p.Challenge,
			// The token family is fixed now, so a replay of this code can find
			// and revoke whatever the first redemption minted.
			Family:    ids.NewID(),
			ExpiresAt: time.Now().UTC().Add(authorizationCodeTTL),
		}); err != nil {
			return err
		}
		// Registration is unauthenticated, so a client row is owned by nobody. The
		// first user to approve it is the closest thing it has to an owner, and the
		// statement's own IS NULL guard makes every later approval a no-op.
		return q.ClaimOAuthClientFirstApproval(ctx, store.ClaimOAuthClientFirstApprovalParams{
			FirstApprovedBy: sql.NullString{String: u.ID, Valid: true},
			ID:              p.ClientID,
		})
	}); err != nil {
		return err
	}

	q := url.Values{"code": {raw}}
	if p.State != "" {
		q.Set("state", p.State)
	}
	// RFC 9207. A client talking to more than one authorization server can check
	// which one actually answered before redeeming the code.
	q.Set("iss", s.issuer(c))
	return c.Redirect(http.StatusFound, appendQuery(p.RedirectURI, q))
}

// consentActor returns the person approving a client and the session ID their
// approval is bound to. requireSession has already validated both.
func (s *Server) consentActor(c echo.Context) (*store.User, string, bool) {
	u, ok := UserFromContext(c)
	if !ok {
		return nil, "", false
	}
	sid, ok := sessionIDFromContext(c)
	if !ok {
		return nil, "", false
	}
	return u, sid, true
}

// consentToken derives a CSRF token from the caller's session ID and the exact
// request being approved.
//
// Deriving rather than storing means no new table and no new secret to configure,
// and it works because the session ID is itself a 32-byte secret the browser will
// not surrender: the cookie is HttpOnly, so no script on any origin can read it.
//
// Mixing in the request is what stops the token from being a session-wide bearer
// approval. A token minted for one consent screen will not verify against a POST
// naming a different client, redirect target, audience, or scope — so it can only
// confirm the decision the user was actually shown.
func consentToken(sessionID string, p authzParams) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"voodoo-consent-v1",
		sessionID,
		p.ClientID,
		p.RedirectURI,
		p.Resource,
		p.Scope,
		p.Challenge,
	}, "\x00")))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func verifyConsentToken(sessionID string, p authzParams, got string) bool {
	want := consentToken(sessionID, p)
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// redirectHost is the host portion of a redirect URI, for display on the consent
// screen. A private-use scheme has no host, so the scheme itself is what the user
// needs to see — it is what names the local application receiving the code.
func redirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Host != "" {
		return u.Host
	}
	return u.Scheme + ":"
}

// appendQuery merges extra parameters into a URI's query string, preserving any the
// client already registered.
func appendQuery(raw string, extra url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		// parseAuthz only ever hands us a URI that parsed at registration time, so
		// this is unreachable; degrade to the bare URI rather than dropping the user
		// on a blank page.
		return raw
	}
	q := u.Query()
	for k, vs := range extra {
		q.Set(k, vs[0])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// humanDuration renders a token lifetime for the consent screen, which needs to
// tell the user in plain words how long their approval lasts.
func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return strconv.Itoa(int(d.Hours())/24) + " days"
	case d >= 2*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " hours"
	default:
		return strconv.Itoa(int(d.Minutes())) + " minutes"
	}
}
