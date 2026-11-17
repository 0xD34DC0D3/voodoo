package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLimiterKey(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"not-an-ip":            "not-an-ip",
	}
	for in, want := range cases {
		if got := limiterKey(in); got != want {
			t.Errorf("limiterKey(%q)=%q want %q", in, got, want)
		}
	}
}

// postLoginFrom posts a failing login with the given peer and X-Forwarded-For.
func (e *testEnv) postLoginFrom(t *testing.T, remote, xff string) int {
	t.Helper()
	form := url.Values{"email": {"nobody@example.com"}, "password": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return e.do(t, req).Code
}

func TestCredentialLimiterReturns429AfterBurst(t *testing.T) {
	e := setup(t)
	for i := range 10 {
		if code := e.postLoginFrom(t, "192.0.2.1:1234", ""); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i+1, code)
		}
	}
	if code := e.postLoginFrom(t, "192.0.2.1:1234", ""); code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", code)
	}
	// Another address has its own bucket.
	if code := e.postLoginFrom(t, "192.0.2.2:1234", ""); code != http.StatusUnauthorized {
		t.Fatalf("other address: status=%d, want 401", code)
	}
}

func TestCredentialLimiterSharesBucketAcrossRoutes(t *testing.T) {
	e := setup(t)
	for range 10 {
		e.postLoginFrom(t, "192.0.2.1:1234", "")
	}
	for _, path := range []string{"/signup", "/reset"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.1:1234"
		if rr := e.do(t, req); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("%s status=%d, want 429", path, rr.Code)
		}
	}
}

func TestCredentialLimiterKeysIPv6On64(t *testing.T) {
	e := setup(t)
	for i := range 10 {
		remote := fmt.Sprintf("[2001:db8:1:2::%x]:1234", i+1)
		if code := e.postLoginFrom(t, remote, ""); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i+1, code)
		}
	}
	if code := e.postLoginFrom(t, "[2001:db8:1:2:ffff::1]:1234", ""); code != http.StatusTooManyRequests {
		t.Fatalf("same /64: status=%d, want 429", code)
	}
	if code := e.postLoginFrom(t, "[2001:db8:1:3::1]:1234", ""); code != http.StatusUnauthorized {
		t.Fatalf("other /64: status=%d, want 401", code)
	}
}

// Behind the local proxy, the client address comes from X-Forwarded-For.
func TestCredentialLimiterTrustsForwardedForFromLoopback(t *testing.T) {
	e := setup(t)
	for range 10 {
		e.postLoginFrom(t, "127.0.0.1:5555", "198.51.100.1")
	}
	if code := e.postLoginFrom(t, "127.0.0.1:5555", "198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", code)
	}
	// A different forwarded client through the same proxy is not throttled.
	if code := e.postLoginFrom(t, "127.0.0.1:5555", "198.51.100.2"); code != http.StatusUnauthorized {
		t.Fatalf("other client: status=%d, want 401", code)
	}
}

// Only loopback is a trusted proxy; a private-range peer cannot pick its bucket.
func TestCredentialLimiterIgnoresForwardedForFromPrivatePeer(t *testing.T) {
	e := setup(t)
	for i := range 10 {
		e.postLoginFrom(t, "10.0.0.5:5555", fmt.Sprintf("198.51.100.%d", i+1))
	}
	if code := e.postLoginFrom(t, "10.0.0.5:5555", "198.51.100.200"); code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429 — spoofed X-Forwarded-For bought a fresh bucket", code)
	}
}

func TestTokenLimiterHasItsOwnBucket(t *testing.T) {
	e := setup(t)
	post := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("grant_type=nope"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.9:1234"
		return e.do(t, req).Code
	}
	for i := range 30 {
		if code := post("/token"); code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status=%d, want 400", i+1, code)
		}
	}
	if code := post("/token"); code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", code)
	}
	// Login from the same address is untouched.
	if code := e.postLoginFrom(t, "192.0.2.9:1234", ""); code != http.StatusUnauthorized {
		t.Fatalf("login status=%d, want 401", code)
	}
}

// /register keys IPv6 on /64 too: a host holding a /64 must not get 2^64 buckets
// on the one unauthenticated endpoint that writes rows.
func TestRegisterLimiterKeysIPv6On64(t *testing.T) {
	e := setup(t)
	post := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/register",
			strings.NewReader(`{"redirect_uris":["https://example.com/cb"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remote
		return e.do(t, req).Code
	}
	for i := range 5 {
		if code := post(fmt.Sprintf("[2001:db8:1:2::%x]:1234", i+1)); code != http.StatusCreated {
			t.Fatalf("registration %d: status=%d, want 201", i+1, code)
		}
	}
	if code := post("[2001:db8:1:2:ffff::1]:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("same /64: status=%d, want 429", code)
	}
	if code := post("[2001:db8:1:3::1]:1234"); code != http.StatusCreated {
		t.Fatalf("other /64: status=%d, want 201", code)
	}
}
