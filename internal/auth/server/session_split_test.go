package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The parent-domain cookie is what sibling hosts see. It answers /me and
// nothing else that a cookie can reach.
func TestParentCookieOnlyProvesIdentity(t *testing.T) {
	e := setup(t)
	_, parent := e.loginCookies(t) // the bootstrap admin

	if rr := e.get(t, "/me", parent); rr.Code != http.StatusOK {
		t.Fatalf("/me with parent cookie status=%d, want 200", rr.Code)
	}
	for _, path := range []string{"/", "/keys", "/connections", "/admin", "/admin/users", "/authorize"} {
		rr := e.get(t, path, parent)
		if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/login") {
			t.Fatalf("GET %s with parent cookie: status=%d location=%q, want redirect to /login",
				path, rr.Code, rr.Header().Get("Location"))
		}
	}
	if rr := e.postForm(t, "/keys", url.Values{"name": {"x"}}, parent); rr.Code != http.StatusFound ||
		!strings.HasPrefix(rr.Header().Get("Location"), "/login") {
		t.Fatalf("POST /keys with parent cookie: status=%d, want redirect to /login", rr.Code)
	}
	if n := e.countRows(t, "api_keys", "name", "x"); n != 0 {
		t.Fatal("parent cookie minted an API key")
	}
}

func TestUICookieDrivesUI(t *testing.T) {
	e := setup(t)
	ui, _ := e.loginCookies(t)
	for _, path := range []string{"/", "/keys", "/admin/users", "/me"} {
		if rr := e.get(t, path, ui); rr.Code != http.StatusOK {
			t.Fatalf("GET %s with UI cookie status=%d, want 200", path, rr.Code)
		}
	}
}

func TestLogoutClearsBothCookies(t *testing.T) {
	for _, which := range []string{"ui", "parent"} {
		t.Run(which, func(t *testing.T) {
			e := setup(t)
			ui, parent := e.loginCookies(t)
			ck := ui
			if which == "parent" {
				ck = parent // a sibling app's logout form
			}
			rr := e.postForm(t, "/logout", nil, ck)
			if rr.Code != http.StatusFound {
				t.Fatalf("logout status=%d", rr.Code)
			}
			cleared := map[string]bool{}
			for _, c := range rr.Result().Cookies() {
				if c.MaxAge < 0 {
					cleared[c.Name] = true
				}
			}
			if !cleared["voodoo_session"] || !cleared["voodoo_ui"] {
				t.Fatalf("logout cleared %v, want both cookies", cleared)
			}
			if rr := e.get(t, "/me", parent); rr.Code != http.StatusUnauthorized {
				t.Fatalf("/me with parent cookie after logout status=%d", rr.Code)
			}
			if rr := e.get(t, "/me", ui); rr.Code != http.StatusUnauthorized {
				t.Fatalf("/me with UI cookie after logout status=%d", rr.Code)
			}
		})
	}
}

// With secure cookies the UI cookie is __Host- prefixed and host-only; the
// identity cookie carries the parent domain.
func TestCookieAttributes(t *testing.T) {
	e := setup(t)
	e.srv.cfg.CookieSecure = true
	e.srv.cfg.CookieDomain = ".example.test"
	e.mkAdmin(t)
	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)

	byName := map[string]*http.Cookie{}
	for _, c := range rr.Result().Cookies() {
		byName[c.Name] = c
	}
	ui, parent := byName["__Host-voodoo_ui"], byName["voodoo_session"]
	if ui == nil || parent == nil {
		t.Fatalf("login set %v, want __Host-voodoo_ui and voodoo_session", byName)
	}
	if ui.Value == parent.Value {
		t.Fatal("UI and parent cookies share a secret")
	}
	if ui.Domain != "" || ui.Path != "/" || !ui.Secure || !ui.HttpOnly || ui.SameSite != http.SameSiteLaxMode {
		t.Fatalf("UI cookie attributes: %+v", ui)
	}
	if parent.Domain != "example.test" || !parent.Secure || !parent.HttpOnly {
		t.Fatalf("parent cookie attributes: %+v", parent)
	}
}
