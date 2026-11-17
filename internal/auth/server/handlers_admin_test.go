package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/0xD34DC0D3/voodoo/internal/auth/password"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

// mkUser inserts a non-admin user and returns their ID. Password is fixed at
// "user-pw" so tests can log in if they need a cookie.
func (e *testEnv) mkUser(t *testing.T, email string) string {
	t.Helper()
	hash, err := password.Hash("user-pw")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.q.CreateUser(context.Background(), store.CreateUserParams{
		ID:           ids.NewID(),
		Email:        email,
		PasswordHash: hash,
		IsAdmin:      false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// userLoginCookie logs in a non-admin user (created via mkUser) and returns
// the session cookie.
func (e *testEnv) userLoginCookie(t *testing.T, email string) *http.Cookie {
	t.Helper()
	form := url.Values{"email": {email}, "password": {"user-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	ck := sessionCookie(rr)
	if ck == nil {
		t.Fatalf("no cookie for %s; status=%d", email, rr.Code)
	}
	return ck
}

func TestAdminAnonymousRedirectsToLogin(t *testing.T) {
	e := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login") {
		t.Fatalf("location=%q want /login...", rr.Header().Get("Location"))
	}
}

func TestAdminNonAdminGets403(t *testing.T) {
	e := setup(t)
	e.mkUser(t, "bob@example.com")
	ck := e.userLoginCookie(t, "bob@example.com")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rr.Code)
	}
}

func TestAdminUsersListsAll(t *testing.T) {
	e := setup(t)
	e.mkUser(t, "bob@example.com")
	ck := e.loginCookie(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "admin@example.com") || !strings.Contains(body, "bob@example.com") {
		t.Fatalf("expected both users in body; got: %s", body)
	}
}

func TestAdminDisableCascadesSessions(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	bobCk := e.userLoginCookie(t, "bob@example.com")
	adminCk := e.loginCookie(t)

	// Sanity: bob can hit /me before disable.
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(bobCk)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("pre-disable /me status=%d", rr.Code)
	}

	// Admin disables bob.
	req = httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/disable", nil)
	req.AddCookie(adminCk)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("disable status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Bob's cookie must no longer authenticate (session row was deleted).
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(bobCk)
	if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-disable /me status=%d", rr.Code)
	}

	// disabled_at must be set in the row.
	u, err := e.q.GetUserByID(context.Background(), bobID)
	if err != nil {
		t.Fatal(err)
	}
	if !u.DisabledAt.Valid {
		t.Fatal("disabled_at was not set")
	}
}

func TestAdminCannotDisableSelf(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	adminID, err := e.q.GetUserByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+adminID.ID+"/disable", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
	u, err := e.q.GetUserByID(context.Background(), adminID.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.DisabledAt.Valid {
		t.Fatal("admin was disabled despite self-disable guard")
	}
}

func TestAdminRevokeSessions(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	bobCk := e.userLoginCookie(t, "bob@example.com")
	adminCk := e.loginCookie(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/sessions/revoke", nil)
	req.AddCookie(adminCk)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("revoke status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(bobCk)
	if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke /me status=%d", rr.Code)
	}

	// Bob can still log back in (account not disabled).
	form := url.Values{"email": {"bob@example.com"}, "password": {"user-pw"}}
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("re-login status=%d", rr.Code)
	}
}

func TestAdminPromoteAndDemote(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	ck := e.loginCookie(t)

	// Promote.
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/promote", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("promote status=%d", rr.Code)
	}
	u, err := e.q.GetUserByID(context.Background(), bobID)
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin {
		t.Fatal("promote did not set is_admin")
	}

	// Demote.
	req = httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/demote", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("demote status=%d", rr.Code)
	}
	u, err = e.q.GetUserByID(context.Background(), bobID)
	if err != nil {
		t.Fatal(err)
	}
	if u.IsAdmin {
		t.Fatal("demote did not clear is_admin")
	}
}

func TestAdminCannotDemoteSelf(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	admin, err := e.q.GetUserByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+admin.ID+"/demote", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
	u, err := e.q.GetUserByID(context.Background(), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin {
		t.Fatal("self-demote guard failed: admin was demoted")
	}
}

func TestAdminInviteCreateShowsLinkOnce(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)

	form := url.Values{"email": {"carol@example.com"}, "expires_in_days": {"3"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/signup?invite=") {
		t.Fatalf("expected signup link in body, got: %s", body)
	}

	// The created invite must exist and be unused.
	invites, err := e.q.ListInvites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 1 {
		t.Fatalf("want 1 invite, got %d", len(invites))
	}
	if invites[0].UsedAt.Valid {
		t.Fatal("new invite should not be used")
	}
	if !invites[0].Email.Valid || invites[0].Email.String != "carol@example.com" {
		t.Fatalf("unexpected invite email: %+v", invites[0].Email)
	}
	// Expires must be roughly +3 days from now.
	delta := time.Until(invites[0].ExpiresAt)
	if delta < 2*24*time.Hour+23*time.Hour || delta > 3*24*time.Hour+time.Minute {
		t.Fatalf("unexpected expires_at: %v (delta %v)", invites[0].ExpiresAt, delta)
	}
}

// The listing tells open from bound invites and shows who signed up with each.
func TestAdminInvitesListShowsKindAndUsage(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	admin, err := e.q.GetUserByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	open := e.mkInvite(t, admin.ID)
	bound := e.mkInviteWith(t, admin.ID, "bound@example.com", time.Now().UTC().Add(time.Hour))
	for _, email := range []string{"o1@example.com", "o2@example.com"} {
		if rr := e.postSignup(t, open, email); rr.Code != http.StatusFound {
			t.Fatalf("open signup status=%d", rr.Code)
		}
	}
	if rr := e.postSignup(t, bound, "bound@example.com"); rr.Code != http.StatusFound {
		t.Fatalf("bound signup status=%d", rr.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/invites", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	body := rr.Body.String()
	for _, want := range []string{">open<", "2 signups", "o1@example.com", "used by bound@example.com", "leave blank for an open link"} {
		if !strings.Contains(strings.ToLower(body), strings.ToLower(want)) {
			t.Errorf("invites page missing %q", want)
		}
	}
}

var inviteLinkRe = regexp.MustCompile(`/signup\?invite=([A-Za-z0-9_%\-]+)`)

// Invite round trip over hashed storage: the link is not in the database in
// replayable form, and a bound one still redeems exactly once.
func TestInviteLinkRedeemsOnceAndIsNotStored(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)

	form := url.Values{"email": {"first@example.com"}, "expires_in_days": {"7"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create invite status=%d body=%s", rr.Code, rr.Body.String())
	}
	m := inviteLinkRe.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatalf("no invite link in body: %s", rr.Body.String())
	}
	token, err := url.QueryUnescape(m[1])
	if err != nil {
		t.Fatal(err)
	}

	if n := e.countRows(t, "invites", "token", token); n != 0 {
		t.Fatalf("invite token found verbatim in invites (%d rows) — stored in plaintext", n)
	}
	if n := e.countRows(t, "invites", "token", ids.HashToken(token)); n != 1 {
		t.Fatalf("want exactly 1 invite row keyed by the token's digest, got %d", n)
	}

	// The signup page accepts the link...
	req = httptest.NewRequest(http.MethodGet, "/signup?invite="+url.QueryEscape(token), nil)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("get signup with valid invite status=%d body=%s", rr.Code, rr.Body.String())
	}
	// ...the stored digest is not a second, equally valid invite...
	req = httptest.NewRequest(http.MethodGet, "/signup?invite="+ids.HashToken(token), nil)
	if rr := e.do(t, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("digest accepted as an invite: status=%d", rr.Code)
	}

	// ...and it redeems exactly once.
	signup := func(email string) *httptest.ResponseRecorder {
		form := url.Values{"invite": {token}, "email": {email}, "password": {"correct-horse-battery"}}
		req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return e.do(t, req)
	}
	rr = signup("first@example.com")
	if rr.Code != http.StatusFound {
		t.Fatalf("first redemption status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sessionCookie(rr) == nil {
		t.Fatal("first redemption set no session cookie")
	}
	if rr := signup("first@example.com"); rr.Code != http.StatusBadRequest {
		t.Fatalf("second redemption status=%d, want 400", rr.Code)
	}
}

func TestAdminInviteRejectsBadExpires(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)

	form := url.Values{"expires_in_days": {"99999"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
}

func TestAdminInviteDelete(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	admin, err := e.q.GetUserByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Insert an invite directly, storing the digest the way postAdminInvites does.
	token, err := e.q.CreateInvite(context.Background(), store.CreateInviteParams{
		Token:     ids.HashToken("tok-" + ids.NewID()),
		Email:     sql.NullString{},
		CreatedBy: admin.ID,
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The delete button carries the stored digest, not a raw token.
	req := httptest.NewRequest(http.MethodPost, "/admin/invites/"+token.Token+"/delete", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("delete status=%d", rr.Code)
	}
	invites, err := e.q.ListInvites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 0 {
		t.Fatalf("expected invite to be deleted, %d remain", len(invites))
	}
}

func TestAdminBearerNonAdminGets403(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)
	bobID := e.mkUser(t, "bob@example.com")
	raw, _ := e.insertKey(t, bobID, sql.NullTime{})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := e.do(t, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rr.Code)
	}
}

// Disable, admin revoke and a completed reset each delete the user's API keys:
// a key minted from a compromised session never expires on its own.
func TestRevocationDeletesAPIKeys(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, e *testEnv, adminCk *http.Cookie, userID string)
	}{
		{"disable", func(t *testing.T, e *testEnv, adminCk *http.Cookie, userID string) {
			req := httptest.NewRequest(http.MethodPost, "/admin/users/"+userID+"/disable", nil)
			req.AddCookie(adminCk)
			if rr := e.do(t, req); rr.Code != http.StatusFound {
				t.Fatalf("disable status=%d", rr.Code)
			}
		}},
		{"revoke", func(t *testing.T, e *testEnv, adminCk *http.Cookie, userID string) {
			req := httptest.NewRequest(http.MethodPost, "/admin/users/"+userID+"/sessions/revoke", nil)
			req.AddCookie(adminCk)
			if rr := e.do(t, req); rr.Code != http.StatusFound {
				t.Fatalf("revoke status=%d", rr.Code)
			}
		}},
		{"reset", func(t *testing.T, e *testEnv, adminCk *http.Cookie, userID string) {
			tok := e.issueReset(t, adminCk, userID)
			if rr := e.postReset(t, tok, "new-password-123456", "new-password-123456"); rr.Code != http.StatusFound {
				t.Fatalf("reset status=%d", rr.Code)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			adminCk := e.loginCookie(t)
			bobID := e.mkUser(t, "bob@example.com")
			raw, _ := e.insertKey(t, bobID, sql.NullTime{})

			tc.run(t, e, adminCk, bobID)

			if n := e.countRows(t, "api_keys", "user_id", bobID); n != 0 {
				t.Fatalf("api_keys rows=%d, want 0", n)
			}
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			req.Header.Set("Authorization", "Bearer "+raw)
			if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
				t.Fatalf("/me with old key status=%d, want 401", rr.Code)
			}
		})
	}
}

// Pages that show a one-time secret must not be cached.
func TestSecretPagesAreNoStore(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	bobID := e.mkUser(t, "bob@example.com")

	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(adminCk)
		return e.do(t, req)
	}
	for path, form := range map[string]url.Values{
		"/keys":                            {"name": {"cli"}},
		"/admin/users/" + bobID + "/reset": nil,
		"/admin/invites":                   {"expires_in_days": {"7"}},
	} {
		rr := post(path, form)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rr.Code)
		}
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control=%q, want no-store", path, got)
		}
	}
}

func TestAdminEnableUser(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	adminCk := e.loginCookie(t)

	for _, action := range []string{"disable", "enable"} {
		req := httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/"+action, nil)
		req.AddCookie(adminCk)
		if rr := e.do(t, req); rr.Code != http.StatusFound {
			t.Fatalf("%s status=%d body=%s", action, rr.Code, rr.Body.String())
		}
	}
	u, err := e.q.GetUserByID(context.Background(), bobID)
	if err != nil {
		t.Fatal(err)
	}
	if u.DisabledAt.Valid {
		t.Fatal("disabled_at still set after enable")
	}
	if code, _ := e.loginStatus(t, "bob@example.com", "user-pw"); code != http.StatusFound {
		t.Fatalf("login after enable status=%d", code)
	}
}

func TestAdminEnableRequiresAdmin(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)
	e.mkUser(t, "bob@example.com")
	carolID := e.mkUser(t, "carol@example.com")
	if _, err := e.db.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC(), carolID); err != nil {
		t.Fatal(err)
	}
	ck := e.userLoginCookie(t, "bob@example.com")

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+carolID+"/enable", nil)
	req.AddCookie(ck)
	if rr := e.do(t, req); rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rr.Code)
	}
	u, err := e.q.GetUserByID(context.Background(), carolID)
	if err != nil {
		t.Fatal(err)
	}
	if !u.DisabledAt.Valid {
		t.Fatal("non-admin re-enabled a user")
	}
}

func TestAdminUsersShowsEnableForDisabled(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	if _, err := e.db.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC(), bobID); err != nil {
		t.Fatal(err)
	}
	ck := e.loginCookie(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if !strings.Contains(rr.Body.String(), `action="/admin/users/`+bobID+`/enable"`) {
		t.Fatalf("no enable form for disabled user: %s", rr.Body.String())
	}
}

func TestAdminUnknownUserIs404(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	for _, action := range []string{"disable", "enable", "sessions/revoke", "promote", "demote", "reset"} {
		req := httptest.NewRequest(http.MethodPost, "/admin/users/no-such-user/"+action, nil)
		req.AddCookie(ck)
		if rr := e.do(t, req); rr.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d want 404", action, rr.Code)
		}
	}
}
