package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// captureLogs points slog at a buffer for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestRequestLogUsesRoutePatternNotURL(t *testing.T) {
	e := setup(t)
	logs := captureLogs(t)

	e.do(t, httptest.NewRequest(http.MethodGet, "/reset?token=SECRET-TOKEN", nil))
	e.do(t, httptest.NewRequest(http.MethodGet, "/nope/SECRET-PATH?code=SECRET-CODE", nil))

	out := logs.String()
	if strings.Contains(out, "SECRET") {
		t.Fatalf("log leaked URL parts:\n%s", out)
	}
	// An unknown path matches the admin group's catch-all, which is still a
	// pattern; the raw path must never appear.
	for _, want := range []string{"method=GET route=/reset status=", "route=/* status=", "dur_ms="} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestLoginEventsOmitSecrets(t *testing.T) {
	e := setup(t)
	e.mkUser(t, "bob@example.com")
	logs := captureLogs(t)

	post := func(pw string) {
		form := url.Values{"email": {"bob@example.com"}, "password": {pw}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		e.do(t, req)
	}
	post("wrong-password-xyz")
	post("user-pw")

	out := logs.String()
	for _, bad := range []string{"wrong-password-xyz", "user-pw", "bob@example.com"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log leaked %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{"auth.login.fail", "reason=bad_password", "msg=auth.login "} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestAdminActionsAreAudited(t *testing.T) {
	e := setup(t)
	bobID := e.mkUser(t, "bob@example.com")
	ck := e.loginCookie(t)
	logs := captureLogs(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/disable", nil)
	req.AddCookie(ck)
	e.do(t, req)
	req = httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/reset", nil)
	req.AddCookie(ck)
	e.do(t, req)

	out := logs.String()
	for _, want := range []string{"msg=admin.users.disable", "msg=admin.users.reset", "target=" + bobID, "actor="} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "token=") {
		t.Fatalf("reset token leaked:\n%s", out)
	}
}

func TestAdminAction(t *testing.T) {
	for path, want := range map[string]string{
		"/admin/users/:id/disable":         "users.disable",
		"/admin/users/:id/sessions/revoke": "users.sessions.revoke",
		"/admin/invites":                   "invites.create",
		"/admin/invites/:token/delete":     "invites.delete",
	} {
		if got := adminAction(path); got != want {
			t.Errorf("adminAction(%q)=%q want %q", path, got, want)
		}
	}
}
