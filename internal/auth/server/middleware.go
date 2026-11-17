package server

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/apikey"
	"github.com/0xD34DC0D3/voodoo/internal/auth/session"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

type authMode int

const (
	authModeHTML authMode = iota
	authModeJSON
)

const (
	ctxUserKey    = "user"
	ctxSessionKey = "session_id"
	ctxAPIKeyKey  = "api_key"
)

var errNoAuth = errors.New("no auth")

// UserFromContext returns the user resolved by the require* middleware.
func UserFromContext(c echo.Context) (*store.User, bool) {
	v := c.Get(ctxUserKey)
	if v == nil {
		return nil, false
	}
	u, ok := v.(*store.User)
	return u, ok
}

// apiKeyInfo identifies the API key a request authenticated with.
type apiKeyInfo struct {
	ID   string
	Name string
}

// APIKeyFromContext returns the key id and name when the request authenticated
// with a bearer API key; false for cookie-authenticated requests.
func APIKeyFromContext(c echo.Context) (apiKeyInfo, bool) {
	k, ok := c.Get(ctxAPIKeyKey).(apiKeyInfo)
	return k, ok
}

// sessionIDFromContext returns the raw UI cookie value requireSession
// authenticated with (not the stored digest — consentToken derives the CSRF
// token from it, which must be something a DB reader cannot obtain).
func sessionIDFromContext(c echo.Context) (string, bool) {
	id, ok := c.Get(ctxSessionKey).(string)
	return id, ok && id != ""
}

// authenticate resolves the current user for voodoo's own routes. Only the
// host-only UI cookie counts; the parent-domain cookie is ignored here, because
// sibling hosts hold it. The bearer token is consulted only when no UI cookie is
// set.
func (s *Server) authenticate(c echo.Context) (*store.User, error) {
	if raw := session.ReadUI(c, s.cfg); raw != "" {
		return s.authenticateSession(c, raw, true)
	}
	return s.authenticateBearerHeader(c)
}

// authenticateIdentity resolves the user for /me, the one route that also
// takes the parent-domain cookie sibling apps forward. Either cookie, else a
// bearer key.
func (s *Server) authenticateIdentity(c echo.Context) (*store.User, error) {
	if raw := session.Read(c); raw != "" {
		return s.authenticateSession(c, raw, false)
	}
	return s.authenticate(c)
}

func (s *Server) authenticateBearerHeader(c echo.Context) (*store.User, error) {
	if raw, ok := apikey.ParseBearer(c.Request().Header.Get("Authorization")); ok {
		return s.authenticateBearer(c, raw)
	}
	return nil, errNoAuth
}

// authenticateSession resolves the user behind a session cookie. raw is the
// cookie value; ui says which cookie it came from. sessions.id and
// sessions.ui_id store digests, so the lookup hashes raw first.
func (s *Server) authenticateSession(c echo.Context, raw string, ui bool) (*store.User, error) {
	ctx := c.Request().Context()
	digest := ids.HashToken(raw)
	var sess store.Session
	var err error
	if ui {
		sess, err = s.q.GetSessionByUIID(ctx, digest)
	} else {
		sess, err = s.q.GetSessionByID(ctx, digest)
	}
	if err != nil {
		return nil, errNoAuth
	}
	now := time.Now().UTC()
	if !sess.ExpiresAt.After(now) {
		_ = s.q.DeleteSession(ctx, sess.ID)
		return nil, errNoAuth
	}
	u, err := s.q.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, errNoAuth
	}
	if u.DisabledAt.Valid {
		return nil, errNoAuth
	}
	_ = s.q.TouchSession(ctx, store.TouchSessionParams{LastUsedAt: now, ID: sess.ID})
	return &u, nil
}

func (s *Server) authenticateBearer(c echo.Context, raw string) (*store.User, error) {
	ctx := c.Request().Context()
	key, err := s.q.GetApiKeyByHash(ctx, apikey.HashOf(raw))
	if err != nil {
		return nil, errNoAuth
	}
	now := time.Now().UTC()
	if key.ExpiresAt.Valid && !key.ExpiresAt.Time.After(now) {
		return nil, errNoAuth
	}
	u, err := s.q.GetUserByID(ctx, key.UserID)
	if err != nil {
		return nil, errNoAuth
	}
	if u.DisabledAt.Valid {
		return nil, errNoAuth
	}
	_ = s.q.TouchApiKey(ctx, store.TouchApiKeyParams{
		LastUsedAt: sql.NullTime{Time: now, Valid: true},
		ID:         key.ID,
	})
	c.Set(ctxAPIKeyKey, apiKeyInfo{ID: key.ID, Name: key.Name})
	return &u, nil
}

// requireUser authenticates with the UI cookie or a bearer API key.
func (s *Server) requireUser(mode authMode) echo.MiddlewareFunc {
	return s.requireWith(s.authenticate, mode)
}

// requireIdentity is requireUser that also accepts the parent-domain cookie.
// It guards /me only: that cookie proves identity to sibling apps and must not
// reach anything else.
func (s *Server) requireIdentity(mode authMode) echo.MiddlewareFunc {
	return s.requireWith(s.authenticateIdentity, mode)
}

func (s *Server) requireWith(auth func(echo.Context) (*store.User, error), mode authMode) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u, err := auth(c)
			if err != nil {
				return s.rejectAuth(c, mode)
			}
			c.Set(ctxUserKey, u)
			return next(c)
		}
	}
}

// requireSession authenticates from the UI cookie alone and publishes the
// cookie value it validated.
//
// The OAuth consent screen needs both halves of that: approving a client is a
// decision only a person at a browser should make, and the CSRF token is derived
// from the session ID — so it has to be an ID that actually authenticated this
// request, not whatever a cookie happens to carry.
func (s *Server) requireSession(mode authMode) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			id := session.ReadUI(c, s.cfg)
			if id == "" {
				return s.rejectAuth(c, mode)
			}
			u, err := s.authenticateSession(c, id, true)
			if err != nil {
				return s.rejectAuth(c, mode)
			}
			c.Set(ctxUserKey, u)
			c.Set(ctxSessionKey, id)
			return next(c)
		}
	}
}

// requireAPIKey authenticates from a bearer API key alone. Token introspection is
// for resource servers, which hold a key; letting a browser session reach it would
// turn it into a way for any logged-in user to test token strings.
func (s *Server) requireAPIKey(mode authMode) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw, ok := apikey.ParseBearer(c.Request().Header.Get("Authorization"))
			if !ok {
				return s.rejectAuth(c, mode)
			}
			u, err := s.authenticateBearer(c, raw)
			if err != nil {
				return s.rejectAuth(c, mode)
			}
			c.Set(ctxUserKey, u)
			return next(c)
		}
	}
}

// requireAdmin authenticates the request and additionally requires that the
// resolved user has is_admin set. A non-admin authenticated user gets 403,
// not a redirect to /login — they don't need to log in again.
func (s *Server) requireAdmin(mode authMode) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			u, err := s.authenticate(c)
			if err != nil {
				return s.rejectAuth(c, mode)
			}
			if !u.IsAdmin {
				return s.rejectAdmin(c, mode)
			}
			c.Set(ctxUserKey, u)
			return next(c)
		}
	}
}

func (s *Server) rejectAuth(c echo.Context, mode authMode) error {
	if mode == authModeJSON {
		return c.NoContent(http.StatusUnauthorized)
	}
	req := c.Request()
	next := req.URL.RequestURI()
	target := "/login?next=" + url.QueryEscape(next)
	return c.Redirect(http.StatusFound, target)
}

func (s *Server) rejectAdmin(c echo.Context, mode authMode) error {
	if mode == authModeJSON {
		return c.NoContent(http.StatusForbidden)
	}
	return c.String(http.StatusForbidden, "forbidden")
}

// safeNext returns next if it is a safe post-login redirect target, empty
// string otherwise. A local path (/..., but not the protocol-relative //...) is
// always allowed. An absolute https:// URL is allowed only when its host is the
// parent domain or one of its subdomains — derived from cookieDomain (e.g.
// ".example.com") so sibling apps like app.example.com can bounce users
// here to log in and get sent back. When allowLocalhost is true (local insecure
// dev), absolute http(s):// URLs pointing at localhost/127.0.0.1 on any port are
// also allowed so sibling apps on other ports can round-trip. Everything else
// (other schemes, foreign hosts, unparseable input) is rejected, keeping
// open-redirect protection intact.
func safeNext(next, cookieDomain string, allowLocalhost bool) string {
	if next == "" {
		return ""
	}
	// Browsers strip tab, CR and LF from URLs and treat "\" as "/", so
	// "/\tevil.com" or "/\evil.com" reach the user as "//evil.com" — an
	// off-site redirect that slips past a bare "//" prefix check. No legitimate
	// target needs any of these, so reject control characters and backslash
	// anywhere in the value, local path or absolute URL alike.
	if strings.ContainsFunc(next, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == '\\'
	}) {
		return ""
	}
	if strings.HasPrefix(next, "/") {
		// Reject protocol-relative ("//evil.com").
		if strings.HasPrefix(next, "//") {
			return ""
		}
		return next
	}
	if allowLocalhost && hostIsLocalhost(next) {
		return next
	}
	if !hostInParentDomain(next, cookieDomain) {
		return ""
	}
	return next
}

// hostIsLocalhost reports whether raw is an absolute http(s):// URL whose host
// is localhost or a loopback address (any port). Used only in local insecure
// dev to permit cross-port redirects; never trusted in production.
func hostIsLocalhost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// hostInParentDomain reports whether raw is an absolute https:// URL whose host
// is cookieDomain's parent domain or a subdomain of it. cookieDomain carries a
// leading dot (".example.com"); an empty cookieDomain trusts no external host.
func hostInParentDomain(raw, cookieDomain string) bool {
	base := strings.TrimPrefix(cookieDomain, ".")
	if base == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	return host == base || strings.HasSuffix(host, "."+base)
}
