package server

import (
	"bytes"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/password"
	"github.com/0xD34DC0D3/voodoo/internal/auth/session"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/auth/views"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

const (
	genericLoginErr  = "invalid email or password"
	invalidInviteErr = "invite is missing, invalid, or already used"
)

// dummyHash is used to keep timing on unknown-email login attempts comparable.
// It is computed lazily so that non-serve invocations (e.g. `voodoo migrate`)
// don't pay the argon2 cost on startup. We panic on failure because a broken
// crypto/rand is a louder problem than a silent timing-leak fallback.
var (
	dummyHashOnce sync.Once
	dummyHashVal  string
)

func getDummyHash() string {
	dummyHashOnce.Do(func() {
		h, err := password.Hash("dummy-password-for-timing")
		if err != nil {
			panic("voodoo: failed to generate dummy password hash: " + err.Error())
		}
		dummyHashVal = h
	})
	return dummyHashVal
}

func (s *Server) render(c echo.Context, status int, tmpl string, data any) error {
	var buf bytes.Buffer
	if err := views.Render(&buf, tmpl, data); err != nil {
		return err
	}
	return c.HTMLBlob(status, buf.Bytes())
}

func (s *Server) pageChrome(c echo.Context, title string) web.Chrome {
	path := c.Path()
	ch := web.Chrome{
		Title:   title,
		Nav:     navFor(path),
		Wide:    wideFor(path),
		Flash:   s.takeFlash(c),
		SiteURL: s.cfg.SiteURL,
	}
	if u, ok := UserFromContext(c); ok {
		ch.UserEmail = u.Email
		ch.IsAdmin = u.IsAdmin
	}
	return ch
}

// navFor maps a route to its active top-level nav section. It works off the
// registered route pattern (e.g. "/admin/users/:id/disable"), so error
// re-renders on POST routes still highlight the right section.
func navFor(path string) string {
	switch {
	case strings.HasPrefix(path, "/admin"):
		return "admin"
	case strings.HasPrefix(path, "/keys"):
		return "keys"
	case strings.HasPrefix(path, "/connections"):
		return "connections"
	case path == "/" || strings.HasPrefix(path, "/settings"):
		return "home"
	default:
		return ""
	}
}

// wideFor reports whether a route renders a table that wants the wider column.
// /authorize is the odd one out: it is not a table, but the consent screen names a
// full resource URI and reads badly wrapped.
func wideFor(path string) bool {
	return path == "/keys" ||
		path == "/connections" ||
		path == "/authorize" ||
		strings.HasPrefix(path, "/admin/users") ||
		strings.HasPrefix(path, "/admin/invites") ||
		strings.HasPrefix(path, "/admin/clients")
}

const flashCookie = "voodoo_flash"

// setFlash stashes a one-shot success message for the page rendered after a
// redirect. It is read and cleared by takeFlash on the next render. Host-only
// (no Domain): it is voodoo's own UI state, not something sibling hosts read
// or may set.
func (s *Server) setFlash(c echo.Context, msg string) {
	c.SetCookie(&http.Cookie{
		Name:     flashCookie,
		Value:    url.QueryEscape(msg),
		Path:     "/",
		MaxAge:   30,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// takeFlash returns and clears any pending flash message.
func (s *Server) takeFlash(c echo.Context) string {
	ck, err := c.Cookie(flashCookie)
	if err != nil || ck == nil || ck.Value == "" {
		return ""
	}
	c.SetCookie(&http.Cookie{
		Name:     flashCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	msg, err := url.QueryUnescape(ck.Value)
	if err != nil {
		return ""
	}
	return msg
}

type loginView struct {
	web.Chrome
	Error string
	Email string
	Next  string
}

func (s *Server) loginView(c echo.Context, errMsg, email, next string) loginView {
	return loginView{Chrome: s.pageChrome(c, "log in"), Error: errMsg, Email: email, Next: next}
}

func (s *Server) getLogin(c echo.Context) error {
	return s.render(c, http.StatusOK, "login.html",
		s.loginView(c, "", "", safeNext(c.QueryParam("next"), s.cfg.CookieDomain, !s.cfg.CookieSecure)))
}

func (s *Server) postLogin(c echo.Context) error {
	email := store.NormalizeEmail(c.FormValue("email"))
	pw := c.FormValue("password")
	next := safeNext(c.FormValue("next"), s.cfg.CookieDomain, !s.cfg.CookieSecure)

	ctx := c.Request().Context()
	// We return 401 deliberately on login form failures so failed attempts are
	// observable in access logs and tests; don't "fix" this to 200 + error body.
	// Unknown and disabled accounts share a path: both burn a hash verification
	// so response timing doesn't reveal whether the account exists.
	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil || u.DisabledAt.Valid {
		dummy := getDummyHash()
		if _, err := s.verifyPassword(c, dummy, pw); isHashBusy(err) {
			return err
		}
		if err == nil {
			logEvent(c, "auth.login.fail", "reason", "disabled", "user", u.ID)
		} else {
			logEvent(c, "auth.login.fail", "reason", "unknown_email")
		}
		return s.render(c, http.StatusUnauthorized, "login.html",
			s.loginView(c, genericLoginErr, email, next))
	}
	ok, err := s.verifyPassword(c, u.PasswordHash, pw)
	if isHashBusy(err) {
		return err
	}
	if err != nil || !ok {
		logEvent(c, "auth.login.fail", "reason", "bad_password", "user", u.ID)
		return s.render(c, http.StatusUnauthorized, "login.html",
			s.loginView(c, genericLoginErr, email, next))
	}

	if err := s.startSession(c, u.ID); err != nil {
		return err
	}
	logEvent(c, "auth.login", "user", u.ID)

	dest := "/"
	if next != "" {
		dest = next
	}
	return c.Redirect(http.StatusFound, dest)
}

type homeView struct {
	web.Chrome
	Error     string
	Created   string
	Timezone  string
	Timezones []string
}

func (s *Server) getHome(c echo.Context) error {
	return s.renderHome(c, http.StatusOK, "")
}

func (s *Server) renderHome(c echo.Context, status int, errMsg string) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	// A stored zone outside the canonical list (an alias set via the API,
	// say) still has to appear — and stay selected — in the dropdown.
	zones := timezones
	if !slices.Contains(zones, u.Timezone) {
		zones = append([]string{u.Timezone}, zones...)
	}
	return s.render(c, status, "home.html", homeView{
		Chrome:    s.pageChrome(c, "home"),
		Error:     errMsg,
		Created:   timeStr(u.CreatedAt),
		Timezone:  u.Timezone,
		Timezones: zones,
	})
}

func (s *Server) postSettingsTimezone(c echo.Context) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	tz := strings.TrimSpace(c.FormValue("timezone"))
	if tz == "" {
		tz = "UTC"
	}
	// time.LoadLocation("Local") resolves to the *server's* timezone — never
	// what a user means, and unstable across deploys — so reject it before
	// LoadLocation can accept it.
	if strings.EqualFold(tz, "Local") {
		return s.renderHome(c, http.StatusBadRequest,
			"unknown timezone — use an IANA name like America/Chicago")
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return s.renderHome(c, http.StatusBadRequest,
			"unknown timezone — use an IANA name like America/Chicago")
	}
	if err := s.q.SetUserTimezone(c.Request().Context(), store.SetUserTimezoneParams{
		Timezone: tz,
		ID:       u.ID,
	}); err != nil {
		return err
	}
	s.setFlash(c, "Timezone saved.")
	return c.Redirect(http.StatusFound, "/")
}

// postLogout revokes the session and clears both cookies. Either cookie names
// the session, so a sibling app's logout form (which only has the
// parent-domain cookie in mind) ends the whole session.
func (s *Server) postLogout(c echo.Context) error {
	ctx := c.Request().Context()
	if raw := session.Read(c); raw != "" {
		_ = s.q.DeleteSession(ctx, ids.HashToken(raw))
	}
	if raw := session.ReadUI(c, s.cfg); raw != "" {
		_ = s.q.DeleteSessionByUIID(ctx, ids.HashToken(raw))
	}
	session.Clear(c, s.cfg)
	logEvent(c, "auth.logout")
	return c.Redirect(http.StatusFound, "/login")
}

type signupView struct {
	web.Chrome
	Error  string
	Invite string
	Email  string
	// Bound marks an email-bound invite: Email is fixed and shown read-only.
	Bound bool
	Next  string
}

func (s *Server) signupView(c echo.Context, errMsg, invite, email string, bound bool, next string) signupView {
	return signupView{Chrome: s.pageChrome(c, "sign up"), Error: errMsg, Invite: invite, Email: email, Bound: bound, Next: next}
}

func (s *Server) getSignup(c echo.Context) error {
	token := c.QueryParam("invite")
	next := safeNext(c.QueryParam("next"), s.cfg.CookieDomain, !s.cfg.CookieSecure)
	inv, err := s.lookupInvite(c, token)
	if err != nil {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, invalidInviteErr, "", "", false, next))
	}
	email := ""
	if inv.Email.Valid {
		email = inv.Email.String
	}
	return s.render(c, http.StatusOK, "signup.html",
		s.signupView(c, "", token, email, inv.Email.Valid, next))
}

func (s *Server) postSignup(c echo.Context) error {
	token := c.FormValue("invite")
	email := store.NormalizeEmail(c.FormValue("email"))
	pw := c.FormValue("password")
	next := safeNext(c.FormValue("next"), s.cfg.CookieDomain, !s.cfg.CookieSecure)

	inv, err := s.lookupInvite(c, token)
	if err != nil {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, invalidInviteErr, "", "", false, next))
	}
	// A bound invite only signs up its own email, whatever the form says.
	if inv.Email.Valid && email != inv.Email.String {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, "this invite is for a different email", token, inv.Email.String, true, next))
	}
	if email == "" || pw == "" {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, "email and password are required", token, email, inv.Email.Valid, next))
	}
	if err := password.CheckNew(pw); err != nil {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, err.Error(), token, email, inv.Email.Valid, next))
	}

	hash, err := s.hashPassword(c, pw)
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qtx := s.q.WithTx(tx)

	u, err := qtx.CreateUser(ctx, store.CreateUserParams{
		ID:           ids.NewID(),
		Email:        email,
		PasswordHash: hash,
		IsAdmin:      false,
		InviteToken:  sql.NullString{String: inv.Token, Valid: true},
	})
	if err != nil {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, "could not create account (email may already be taken)", token, email, inv.Email.Valid, next))
	}

	// ExpiresAt below is the "expires_at > ?" threshold, not a new expiry.
	now := time.Now().UTC()
	_, err = qtx.ConsumeInvite(ctx, store.ConsumeInviteParams{
		UsedAt:    sql.NullTime{Time: now, Valid: true},
		UsedBy:    sql.NullString{String: u.ID, Valid: true},
		Token:     ids.HashToken(token),
		ExpiresAt: now,
	})
	if err != nil {
		return s.render(c, http.StatusBadRequest, "signup.html",
			s.signupView(c, invalidInviteErr, "", "", false, next))
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	logEvent(c, "auth.signup", "user", u.ID)

	if err := s.startSession(c, u.ID); err != nil {
		return err
	}
	dest := "/"
	if next != "" {
		dest = next
	}
	return c.Redirect(http.StatusFound, dest)
}

func (s *Server) getMe(c echo.Context) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"id":       u.ID,
		"email":    u.Email,
		"is_admin": u.IsAdmin,
		"timezone": u.Timezone,
	})
}

// startSession mints a session and hands the browser its two cookies, each with
// its own random secret. sessions.id and sessions.ui_id hold only digests.
func (s *Server) startSession(c echo.Context, userID string) error {
	raw, uiRaw := ids.NewToken(), ids.NewToken()
	now := time.Now().UTC()
	expires := now.Add(s.cfg.SessionTTL)
	_, err := s.q.CreateSession(c.Request().Context(), store.CreateSessionParams{
		ID:        ids.HashToken(raw),
		UiID:      ids.HashToken(uiRaw),
		UserID:    userID,
		ExpiresAt: expires,
		UserAgent: c.Request().UserAgent(),
		Ip:        c.RealIP(),
	})
	if err != nil {
		return err
	}
	session.Set(c, s.cfg, raw, uiRaw, expires)
	return nil
}

// lookupInvite returns the invite row if the token references an unexpired
// invite that is open or, if bound to an email, unused; otherwise an error. token is the raw link value; the
// returned row's Token field is its digest, not a usable invite.
func (s *Server) lookupInvite(c echo.Context, token string) (store.Invite, error) {
	if token == "" {
		return store.Invite{}, errors.New("missing token")
	}
	inv, err := s.q.GetInviteByToken(c.Request().Context(), ids.HashToken(token))
	if err != nil {
		return store.Invite{}, err
	}
	if inv.Email.Valid && inv.UsedAt.Valid {
		return store.Invite{}, errors.New("already used")
	}
	if !inv.ExpiresAt.After(time.Now().UTC()) {
		return store.Invite{}, errors.New("expired")
	}
	return inv, nil
}
