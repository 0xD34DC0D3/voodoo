package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

var resetLinkRe = regexp.MustCompile(`/reset\?token=([A-Za-z0-9_\-]+)`)

// mkReset inserts a password_resets row directly (storing the digest, like
// mkInvite) and returns the raw token for the link.
func (e *testEnv) mkReset(t *testing.T, userID string, expires time.Time) string {
	t.Helper()
	token := "reset-" + ids.NewID()
	_, err := e.q.CreatePasswordReset(context.Background(), store.CreatePasswordResetParams{
		Token:     ids.HashToken(token),
		UserID:    userID,
		CreatedBy: userID,
		ExpiresAt: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// issueReset drives the admin handler and returns the token from the one-time
// link it renders.
func (e *testEnv) issueReset(t *testing.T, adminCk *http.Cookie, userID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+userID+"/reset", nil)
	req.AddCookie(adminCk)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("issue reset status=%d body=%s", rr.Code, rr.Body.String())
	}
	m := resetLinkRe.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatalf("no reset link in body: %s", rr.Body.String())
	}
	tok, err := url.QueryUnescape(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *testEnv) postReset(t *testing.T, token, pw, confirm string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {token}, "password": {pw}, "confirm": {confirm}}
	req := httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(t, req)
}

// loginStatus reports the status of a login attempt (302 on success, 401 on bad
// credentials) and returns the resulting session cookie if any.
func (e *testEnv) loginStatus(t *testing.T, email, pw string) (int, *http.Cookie) {
	t.Helper()
	form := url.Values{"email": {email}, "password": {pw}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	return rr.Code, sessionCookie(rr)
}

func TestAdminIssuePasswordResetShowsLinkOnce(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	bobID := e.mkUser(t, "bob@example.com")

	tok := e.issueReset(t, adminCk, bobID)

	pr, err := e.q.GetPasswordResetByToken(context.Background(), ids.HashToken(tok))
	if err != nil {
		t.Fatalf("reset row not found: %v", err)
	}
	if pr.UserID != bobID {
		t.Fatalf("reset bound to %q, want %q", pr.UserID, bobID)
	}
	if pr.UsedAt.Valid {
		t.Fatal("new reset should be unused")
	}
	if delta := time.Until(pr.ExpiresAt); delta <= 0 || delta > passwordResetTTL+time.Minute {
		t.Fatalf("unexpected expiry delta %v", delta)
	}
}

// Reset link end to end over hashed storage: the raw token is nowhere in
// password_resets, and the link still resets the password exactly once.
func TestResetLinkWorksAndIsNotStored(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	bobID := e.mkUser(t, "bob@example.com")

	token := e.issueReset(t, adminCk, bobID)

	if n := e.countRows(t, "password_resets", "token", token); n != 0 {
		t.Fatalf("reset token found verbatim in password_resets (%d rows) — stored in plaintext", n)
	}
	if n := e.countRows(t, "password_resets", "token", ids.HashToken(token)); n != 1 {
		t.Fatalf("want exactly 1 reset row keyed by the token's digest, got %d", n)
	}

	// The stored digest must not itself open the form — otherwise a database
	// reader still holds a takeover.
	req := httptest.NewRequest(http.MethodGet, "/reset?token="+ids.HashToken(token), nil)
	if rr := e.do(t, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("digest accepted as a reset token: status=%d", rr.Code)
	}

	// The real link serves the form and completes the reset.
	req = httptest.NewRequest(http.MethodGet, "/reset?token="+url.QueryEscape(token), nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get reset status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `name="password"`) {
		t.Fatalf("reset form not shown: %s", rr.Body.String())
	}
	if rr := e.postReset(t, token, "hashed-pw-123456", "hashed-pw-123456"); rr.Code != http.StatusFound {
		t.Fatalf("post reset status=%d body=%s", rr.Code, rr.Body.String())
	}

	// The new password is live and the row is consumed, so the link is spent.
	if code, ck := e.loginStatus(t, "bob@example.com", "hashed-pw-123456"); code != http.StatusFound || ck == nil {
		t.Fatalf("login with new password status=%d cookie=%v", code, ck)
	}
	if rr := e.postReset(t, token, "again-pw-123456", "again-pw-123456"); rr.Code != http.StatusBadRequest {
		t.Fatalf("reused reset link status=%d, want 400", rr.Code)
	}
}

func TestPasswordResetFlowRevokesSessions(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	bobCk := e.userLoginCookie(t, "bob@example.com")
	token := e.mkReset(t, bobID, time.Now().UTC().Add(time.Hour))

	// The form renders for a valid token.
	req := httptest.NewRequest(http.MethodGet, "/reset?token="+url.QueryEscape(token), nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get reset status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `name="password"`) {
		t.Fatalf("reset form not shown: %s", rr.Body.String())
	}

	// Complete the reset.
	rr = e.postReset(t, token, "new-password-123456", "new-password-123456")
	if rr.Code != http.StatusFound {
		t.Fatalf("post reset status=%d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("redirect to %q, want /login", loc)
	}

	// Bob's pre-existing session must be revoked.
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(bobCk)
	if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("old session /me status=%d, want 401", rr.Code)
	}

	// Old password no longer works; new password does.
	if code, _ := e.loginStatus(t, "bob@example.com", "user-pw"); code != http.StatusUnauthorized {
		t.Fatalf("old password login status=%d, want 401", code)
	}
	if code, ck := e.loginStatus(t, "bob@example.com", "new-password-123456"); code != http.StatusFound || ck == nil {
		t.Fatalf("new password login status=%d cookie=%v", code, ck)
	}

	// The token is now marked used.
	pr, err := e.q.GetPasswordResetByToken(context.Background(), ids.HashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if !pr.UsedAt.Valid {
		t.Fatal("token not marked used after reset")
	}
}

func TestPasswordResetTokenIsSingleUse(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	token := e.mkReset(t, bobID, time.Now().UTC().Add(time.Hour))

	if rr := e.postReset(t, token, "first-pw-123456", "first-pw-123456"); rr.Code != http.StatusFound {
		t.Fatalf("first reset status=%d", rr.Code)
	}
	// Second use of the same token must be rejected and must not change the
	// password again.
	rr := e.postReset(t, token, "second-pw-123456", "second-pw-123456")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("reused token status=%d, want 400", rr.Code)
	}
	if code, _ := e.loginStatus(t, "bob@example.com", "second-pw-123456"); code != http.StatusUnauthorized {
		t.Fatalf("second password should not work, login status=%d", code)
	}
	if code, _ := e.loginStatus(t, "bob@example.com", "first-pw-123456"); code != http.StatusFound {
		t.Fatalf("first password should still work, login status=%d", code)
	}
}

func TestPasswordResetExpiredToken(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	token := e.mkReset(t, bobID, time.Now().UTC().Add(-time.Minute))

	req := httptest.NewRequest(http.MethodGet, "/reset?token="+url.QueryEscape(token), nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("get expired status=%d, want 400", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `name="password"`) {
		t.Fatal("form should be hidden for an expired token")
	}
	if rr := e.postReset(t, token, "new-password-123456", "new-password-123456"); rr.Code != http.StatusBadRequest {
		t.Fatalf("post expired status=%d, want 400", rr.Code)
	}
}

func TestPasswordResetMismatchKeepsForm(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	token := e.mkReset(t, bobID, time.Now().UTC().Add(time.Hour))

	rr := e.postReset(t, token, "new-password-123456", "different-password-1")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mismatch status=%d, want 400", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "passwords do not match") {
		t.Fatalf("expected mismatch error, got: %s", body)
	}
	// Token preserved in the form so the user can retry.
	if !strings.Contains(body, token) {
		t.Fatal("token not preserved in form after mismatch")
	}
	// Nothing changed: original password still works, token still unused.
	if code, _ := e.loginStatus(t, "bob@example.com", "user-pw"); code != http.StatusFound {
		t.Fatalf("original password should still work, status=%d", code)
	}
	pr, err := e.q.GetPasswordResetByToken(context.Background(), ids.HashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if pr.UsedAt.Valid {
		t.Fatal("token should remain unused after a failed reset")
	}
}

func TestPasswordResetBadTokenHidesForm(t *testing.T) {
	e := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/reset?token=does-not-exist", nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `name="password"`) {
		t.Fatal("form should be hidden for an unknown token")
	}
}

func TestAdminReissueInvalidatesPriorReset(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	bobID := e.mkUser(t, "bob@example.com")

	first := e.issueReset(t, adminCk, bobID)
	second := e.issueReset(t, adminCk, bobID)
	if first == second {
		t.Fatal("reissue produced the same token")
	}

	// The first link is now dead; only the most recent one resolves.
	req := httptest.NewRequest(http.MethodGet, "/reset?token="+url.QueryEscape(first), nil)
	if rr := e.do(t, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("stale link status=%d, want 400", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/reset?token="+url.QueryEscape(second), nil)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("current link status=%d, want 200", rr.Code)
	}
}

func TestPasswordResetRejectsShortPassword(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	bobID := e.mkUser(t, "bob@example.com")
	token := e.issueReset(t, adminCk, bobID)

	rr := e.postReset(t, token, "short-password", "short-password")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "at least 15") {
		t.Fatalf("status=%d body=%s, want 400 with length error", rr.Code, rr.Body.String())
	}
}
