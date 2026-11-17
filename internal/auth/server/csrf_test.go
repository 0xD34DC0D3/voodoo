package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCrossOriginPostRejected(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	cases := []struct {
		name   string
		header map[string]string
	}{
		{"sec-fetch-site cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"sec-fetch-site same-site", map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"foreign origin, no sec-fetch-site", map[string]string{"Origin": "https://evil.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/keys", nil)
			req.AddCookie(ck)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			if rr := e.do(t, req); rr.Code != http.StatusForbidden {
				t.Fatalf("status=%d want 403", rr.Code)
			}
		})
	}
}

func TestSameOriginPostAllowed(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(ck)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rr.Code)
	}
}

// The OAuth machine endpoints are called cross-origin by design; the check must
// not reach them. Each still fails on its own terms (no credentials), just not 403.
func TestCrossOriginBypassRoutes(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/token", "/register", "/introspect", "/revoke"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			req.Header.Set("Origin", "https://client.test")
			if rr := e.do(t, req); rr.Code == http.StatusForbidden {
				t.Fatalf("status=403; %s must bypass the cross-origin check", path)
			}
		})
	}
}

// Admin actions by API key carry no browser headers and must keep working.
func TestAdminByAPIKeyPassesCrossOriginCheck(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	bobID := e.mkUser(t, "bob@example.com")
	raw, _ := e.insertKey(t, adminID, sql.NullTime{})

	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+bobID+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if rr := e.do(t, req); rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rr.Code)
	}
}

// Sibling apps on the cookie's parent domain host a logout form that posts here.
func TestSiblingLogout(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		origin string
		site   string
		want   int
	}{
		{"sibling host", "/logout", "https://app.example.test", "same-site", http.StatusFound},
		{"parent domain", "/logout", "https://example.test", "same-site", http.StatusFound},
		{"sibling, no sec-fetch-site", "/logout", "https://app.example.test", "", http.StatusFound},
		{"cross-site", "/logout", "https://evil.test", "cross-site", http.StatusForbidden},
		{"suffix spoof", "/logout", "https://evilexample.test", "cross-site", http.StatusForbidden},
		{"sibling over http", "/logout", "http://app.example.test", "same-site", http.StatusForbidden},
		{"sibling on another route", "/keys", "https://app.example.test", "same-site", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			e.srv.cfg.CookieDomain = ".example.test"
			ck := e.loginCookie(t)
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.AddCookie(ck)
			req.Header.Set("Origin", tc.origin)
			if tc.site != "" {
				req.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if rr := e.do(t, req); rr.Code != tc.want {
				t.Fatalf("status=%d want %d", rr.Code, tc.want)
			}
		})
	}
}
