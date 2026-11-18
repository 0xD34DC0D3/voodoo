package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/0xD34DC0D3/voodoo/internal/auth/config"
	"github.com/0xD34DC0D3/voodoo/internal/auth/password"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
	"github.com/0xD34DC0D3/voodoo/migrations"
)

type testEnv struct {
	srv *Server
	db  *sql.DB
	q   *store.Queries
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "voodoo.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := &config.Config{
		DBPath:       dbPath,
		Port:         0,
		CookieSecure: false,
		SiteURL:      "https://site.example",
		SessionTTL:   24 * time.Hour,
		// CookieSecure=false also puts OAuth resource policy into its
		// localhost-permitting mode, which is what makes testResource valid.
		OAuthAccessTTL:  time.Hour,
		OAuthRefreshTTL: 30 * 24 * time.Hour,
	}
	srv := New(cfg, db)
	return &testEnv{srv: srv, db: db, q: store.New(db)}
}

// mkAdmin creates a bootstrap admin user and returns their ID.
func (e *testEnv) mkAdmin(t *testing.T) string {
	t.Helper()
	hash, err := password.Hash("admin-pw")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.q.CreateUser(context.Background(), store.CreateUserParams{
		ID:           ids.NewID(),
		Email:        "admin@example.com",
		PasswordHash: hash,
		IsAdmin:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// mkInvite inserts a fresh open invite for adminID and returns the raw token
// for the link; the row stores its digest, as postAdminInvites does.
func (e *testEnv) mkInvite(t *testing.T, adminID string) string {
	t.Helper()
	return e.mkInviteWith(t, adminID, "", time.Now().UTC().Add(7*24*time.Hour))
}

// mkInviteWith is mkInvite with an email binding ("" for open) and expiry.
func (e *testEnv) mkInviteWith(t *testing.T, adminID, email string, expires time.Time) string {
	t.Helper()
	token := "invite-" + ids.NewID()
	_, err := e.db.ExecContext(context.Background(),
		`INSERT INTO invites (token, email, created_by, expires_at) VALUES (?, NULLIF(?, ''), ?, ?)`,
		ids.HashToken(token), email, adminID, expires,
	)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (e *testEnv) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rr, req)
	return rr
}

// countRows returns how many rows in table have col exactly equal to val.
// Lets the hashing tests ask "is this literal secret in the database?".
func (e *testEnv) countRows(t *testing.T, table, col, val string) int {
	t.Helper()
	var n int
	// #nosec G201 -- table and col are test-supplied literals, never input.
	if err := e.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE `+col+` = ?`, val).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// sessionCookie returns the UI cookie a login set: the one voodoo's own routes
// take. parentCookie returns the parent-domain one sibling apps forward to /me.
func sessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	return namedCookie(rr, "voodoo_ui")
}

func parentCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	return namedCookie(rr, "voodoo_session")
}

func namedCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestSignupLoginMeLogout(t *testing.T) {
	e := setup(t)
	admin := e.mkAdmin(t)
	token := e.mkInvite(t, admin)

	// signup
	form := url.Values{"invite": {token}, "email": {"alice@example.com"}, "password": {"correct-horse-battery"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("signup status=%d body=%s", rr.Code, rr.Body.String())
	}
	ck := sessionCookie(rr)
	if ck == nil {
		t.Fatal("signup did not set session cookie")
	}

	// /me
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(ck)
	rr = e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/me status=%d", rr.Code)
	}
	var me struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		IsAdmin bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if me.Email != "alice@example.com" || me.IsAdmin {
		t.Fatalf("unexpected me: %+v", me)
	}

	// logout
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(ck)
	rr = e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("logout status=%d", rr.Code)
	}

	// /me after logout (server has deleted session row)
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(ck)
	rr = e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/me after logout status=%d", rr.Code)
	}
}

func TestSignupBadInvite(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)

	form := url.Values{"invite": {"nope"}, "email": {"x@example.com"}, "password": {"pw"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code < 400 || rr.Code >= 500 {
		t.Fatalf("expected 4xx, got %d", rr.Code)
	}
}

func (e *testEnv) postSignup(t *testing.T, token, email string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"invite": {token}, "email": {email}, "password": {"correct-horse-battery"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(t, req)
}

// inviteOf returns the invite digest the account for email was created from.
func (e *testEnv) inviteOf(t *testing.T, email string) string {
	t.Helper()
	u, err := e.q.GetUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("no account for %s: %v", email, err)
	}
	return u.InviteToken.String
}

func TestSignupBoundInviteSingleUse(t *testing.T) {
	e := setup(t)
	token := e.mkInviteWith(t, e.mkAdmin(t), "a@example.com", time.Now().UTC().Add(time.Hour))

	if rr := e.postSignup(t, token, " A@Example.com "); rr.Code != http.StatusFound {
		t.Fatalf("first signup status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := e.inviteOf(t, "a@example.com"); got != ids.HashToken(token) {
		t.Fatalf("account not recorded against invite: %q", got)
	}
	// Reuse fails, even with the bound email.
	if rr := e.postSignup(t, token, "a@example.com"); rr.Code != http.StatusBadRequest {
		t.Fatalf("reuse status=%d, want 400", rr.Code)
	}
}

func TestSignupBoundInviteRejectsOtherEmail(t *testing.T) {
	e := setup(t)
	token := e.mkInviteWith(t, e.mkAdmin(t), "a@example.com", time.Now().UTC().Add(time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/signup?invite="+url.QueryEscape(token), nil)
	rr := e.do(t, req)
	if body := rr.Body.String(); rr.Code != http.StatusOK ||
		!strings.Contains(body, `value="a@example.com"`) || !strings.Contains(body, "readonly") {
		t.Fatalf("signup page should show the bound email read-only: status=%d body=%s", rr.Code, body)
	}

	// A tampered form posting another email is refused and creates nothing.
	if rr := e.postSignup(t, token, "b@example.com"); rr.Code != http.StatusBadRequest {
		t.Fatalf("other email status=%d, want 400", rr.Code)
	}
	if _, err := e.q.GetUserByEmail(context.Background(), "b@example.com"); err == nil {
		t.Fatal("bound invite created an account for another email")
	}
	// The invite is still usable by its own email.
	if rr := e.postSignup(t, token, "a@example.com"); rr.Code != http.StatusFound {
		t.Fatalf("bound email status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSignupOpenInviteMultiUse(t *testing.T) {
	e := setup(t)
	token := e.mkInvite(t, e.mkAdmin(t))

	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if rr := e.postSignup(t, token, email); rr.Code != http.StatusFound {
			t.Fatalf("signup %s status=%d body=%s", email, rr.Code, rr.Body.String())
		}
		if got := e.inviteOf(t, email); got != ids.HashToken(token) {
			t.Fatalf("%s not recorded against invite: %q", email, got)
		}
	}
	invites, err := e.q.ListInvites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 1 || invites[0].Signups != 3 {
		t.Fatalf("want 1 invite with 3 signups, got %+v", invites)
	}
}

func TestSignupOpenInviteExpiredOrRevoked(t *testing.T) {
	e := setup(t)
	admin := e.mkAdmin(t)

	expired := e.mkInviteWith(t, admin, "", time.Now().UTC().Add(-time.Minute))
	if rr := e.postSignup(t, expired, "a@example.com"); rr.Code != http.StatusBadRequest {
		t.Fatalf("expired open invite status=%d, want 400", rr.Code)
	}

	revoked := e.mkInvite(t, admin)
	if rr := e.postSignup(t, revoked, "b@example.com"); rr.Code != http.StatusFound {
		t.Fatalf("open invite status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := e.q.DeleteInvite(context.Background(), ids.HashToken(revoked)); err != nil {
		t.Fatal(err)
	}
	if rr := e.postSignup(t, revoked, "c@example.com"); rr.Code != http.StatusBadRequest {
		t.Fatalf("revoked open invite status=%d, want 400", rr.Code)
	}
	for _, email := range []string{"a@example.com", "c@example.com"} {
		if _, err := e.q.GetUserByEmail(context.Background(), email); err == nil {
			t.Fatalf("account created for %s", email)
		}
	}
}

func TestLoginWrongPasswordGeneric(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)

	form := url.Values{"email": {"admin@example.com"}, "password": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "Wrong email or password.") {
		t.Fatalf("expected generic error in body, got: %s", body)
	}
}

func TestLoginDisabledUserGeneric(t *testing.T) {
	e := setup(t)
	id := e.mkAdmin(t)
	_, err := e.db.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC(), id)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "Wrong email or password.") {
		t.Fatalf("expected generic error, got: %s", body)
	}
	if sessionCookie(rr) != nil {
		t.Fatal("expected no session cookie")
	}
}

func TestLoginUnknownEmailGeneric(t *testing.T) {
	e := setup(t)
	form := url.Values{"email": {"nobody@example.com"}, "password": {"pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestLoginSuccess(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)

	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sessionCookie(rr) == nil {
		t.Fatal("expected session cookie")
	}
}

func TestMeUnauthenticatedJSON(t *testing.T) {
	e := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestSettingsTimezone(t *testing.T) {
	e := setup(t)
	id := e.mkAdmin(t)

	// log in
	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	ck := sessionCookie(rr)
	if ck == nil {
		t.Fatal("no cookie after login")
	}

	tzOf := func() string {
		t.Helper()
		var tz string
		if err := e.db.QueryRow(`SELECT timezone FROM users WHERE id = ?`, id).Scan(&tz); err != nil {
			t.Fatal(err)
		}
		return tz
	}
	post := func(tz string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"timezone": {tz}}
		req := httptest.NewRequest(http.MethodPost, "/settings/timezone", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(ck)
		return e.do(t, req)
	}

	// invalid tz is rejected with an error and the column stays UTC
	rr = post("Not/AZone")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid tz status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Unknown timezone") {
		t.Fatalf("expected timezone error in body, got: %s", rr.Body.String())
	}
	if got := tzOf(); got != "UTC" {
		t.Fatalf("timezone after invalid post = %q, want UTC", got)
	}

	// valid tz persists and redirects home
	rr = post("America/Chicago")
	if rr.Code != http.StatusFound {
		t.Fatalf("valid tz status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := tzOf(); got != "America/Chicago" {
		t.Fatalf("timezone = %q, want America/Chicago", got)
	}

	// home page shows the saved timezone
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	rr = e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("home status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "America/Chicago") {
		t.Fatal("home page does not show saved timezone")
	}

	// empty (whitespace) input resets to UTC
	rr = post("   ")
	if rr.Code != http.StatusFound {
		t.Fatalf("empty tz status=%d", rr.Code)
	}
	if got := tzOf(); got != "UTC" {
		t.Fatalf("timezone after empty post = %q, want UTC", got)
	}

	// "Local" (any case) is the server's timezone, never the user's, even
	// though time.LoadLocation accepts it — rejected like an unknown name.
	for _, tz := range []string{"Local", "local", "LOCAL"} {
		rr = post(tz)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%q status=%d, want 400", tz, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Unknown timezone") {
			t.Fatalf("%q: expected timezone error, got: %s", tz, rr.Body.String())
		}
	}
	if got := tzOf(); got != "UTC" {
		t.Fatalf("timezone after Local post = %q, want UTC", got)
	}
}

// The cookie a browser holds must not be a row in sessions. Someone reading
// voodoo.db, or a backup of it, gets digests they cannot turn back into cookies
// — while the browser that holds the real token still authenticates normally.
func TestSessionCookieIsNotStored(t *testing.T) {
	e := setup(t)
	ck, parent := e.loginCookies(t)

	for _, c := range []struct{ col, raw string }{{"id", parent.Value}, {"ui_id", ck.Value}} {
		for _, col := range []string{"id", "ui_id"} {
			if n := e.countRows(t, "sessions", col, c.raw); n != 0 {
				t.Fatalf("cookie value found verbatim in sessions.%s — session tokens are stored in plaintext", col)
			}
		}
		if n := e.countRows(t, "sessions", c.col, ids.HashToken(c.raw)); n != 1 {
			t.Fatalf("want exactly 1 session row with %s = the cookie's digest, got %d", c.col, n)
		}
	}

	// The digest is not a credential: presenting it as the cookie must fail, or
	// hashing would have bought nothing over storing the token itself.
	for _, c := range []*http.Cookie{
		{Name: "voodoo_session", Value: ids.HashToken(parent.Value)},
		{Name: "voodoo_ui", Value: ids.HashToken(ck.Value)},
	} {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.AddCookie(c)
		if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s digest replayed as a cookie authenticated: status=%d", c.Name, rr.Code)
		}
	}

	// The real cookie still works, on both the shared path and the
	// session-only one (/authorize, via requireSession).
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("/me with real cookie status=%d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code == http.StatusFound &&
		strings.HasPrefix(rr.Header().Get("Location"), "/login") {
		t.Fatal("requireSession bounced a valid cookie to /login")
	}

	// last_used_at moves, which is the assertion that TouchSession also hashes:
	// an unhashed touch would update no row and fail silently.
	var lastUsed sql.NullTime
	if err := e.db.QueryRow(`SELECT last_used_at FROM sessions WHERE ui_id = ?`,
		ids.HashToken(ck.Value)).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Valid {
		t.Fatal("last_used_at never set — TouchSession is matching no row")
	}

	// And logout, which deletes by the same digest, really removes the row.
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("logout status=%d", rr.Code)
	}
	if n := e.countRows(t, "sessions", "ui_id", ids.HashToken(ck.Value)); n != 0 {
		t.Fatalf("logout left %d session rows behind", n)
	}
}

func TestRequireUserDisabledMidSession(t *testing.T) {
	e := setup(t)
	id := e.mkAdmin(t)

	// log in
	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	ck := sessionCookie(rr)
	if ck == nil {
		t.Fatal("no cookie after login")
	}

	// disable user
	if _, err := e.db.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC(), id); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(ck)
	rr = e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestBodyLimitIsGlobal(t *testing.T) {
	e := setup(t)
	body := "email=a%40example.com&password=" + strings.Repeat("x", 65*1024)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", rr.Code)
	}
}

func TestSignupRejectsShortPassword(t *testing.T) {
	e := setup(t)
	token := e.mkInvite(t, e.mkAdmin(t))
	form := url.Values{"invite": {token}, "email": {"a@example.com"}, "password": {"fourteen-chars"}}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "at least 15") {
		t.Fatalf("status=%d body=%s, want 400 with length error", rr.Code, rr.Body.String())
	}
}
