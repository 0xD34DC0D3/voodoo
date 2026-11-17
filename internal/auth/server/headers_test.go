package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCopyKeyScriptServed(t *testing.T) {
	e := setup(t)
	rr := e.do(t, httptest.NewRequest(http.MethodGet, "/static/copy-key.js", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type=%q", ct)
	}
}

// Every response carries the hardening headers: pages, JSON, static files,
// errors and rejected cross-origin posts alike.
func TestSecurityHeaders(t *testing.T) {
	e := setup(t)
	reqs := map[string]*http.Request{
		"login page":     httptest.NewRequest(http.MethodGet, "/login", nil),
		"me unauth json": httptest.NewRequest(http.MethodGet, "/me", nil),
		"static":         httptest.NewRequest(http.MethodGet, "/static/style.css", nil),
		"not found":      httptest.NewRequest(http.MethodGet, "/nope", nil),
		"token":          httptest.NewRequest(http.MethodPost, "/token", nil),
	}
	xs := httptest.NewRequest(http.MethodPost, "/keys", nil)
	xs.Header.Set("Sec-Fetch-Site", "cross-site")
	reqs["cross-site reject"] = xs

	for name, req := range reqs {
		t.Run(name, func(t *testing.T) {
			h := e.do(t, req).Header()
			csp := h.Get("Content-Security-Policy")
			for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'"} {
				if !strings.Contains(csp, want) {
					t.Errorf("CSP %q lacks %q", csp, want)
				}
			}
			if strings.Contains(csp, "form-action") || strings.Contains(csp, "unsafe-inline") {
				t.Errorf("CSP %q must not set form-action or unsafe-inline", csp)
			}
			if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options=%q", got)
			}
			if got := h.Get("Referrer-Policy"); got != "same-origin" {
				t.Errorf("Referrer-Policy=%q", got)
			}
		})
	}
}

// The CSP forbids inline script, so no page may carry one.
func TestKeysNewHasNoInlineScript(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	req := httptest.NewRequest(http.MethodPost, "/keys", strings.NewReader("name=k"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, `src="/static/copy-key.js"`) {
		t.Fatalf("expected external copy-key script only")
	}
}

// The flash cookie is voodoo's own UI state: host-only even when the session
// cookie is scoped to the parent domain.
func TestFlashCookieHostOnly(t *testing.T) {
	e := setup(t)
	e.srv.cfg.CookieDomain = ".example.test"
	ck := e.loginCookie(t)
	req := httptest.NewRequest(http.MethodPost, "/settings/timezone", strings.NewReader("timezone=UTC"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	var found bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == flashCookie {
			found = true
			if c.Domain != "" {
				t.Fatalf("flash cookie Domain=%q, want host-only", c.Domain)
			}
		}
	}
	if !found {
		t.Fatalf("no flash cookie; status=%d", rr.Code)
	}
}
