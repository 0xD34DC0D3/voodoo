package voodooauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// fakeVoodoo answers /me like voodoo: cookie "good" is a user, cookie "boss"
// an admin, key "ak_good" a user via API key; anything else is 401. status,
// when set, overrides the answer (to simulate an outage).
type fakeVoodoo struct {
	*httptest.Server
	calls  atomic.Int32
	status atomic.Int32
}

func newFake(t *testing.T) *fakeVoodoo {
	f := &fakeVoodoo{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me" {
			http.NotFound(w, r)
			return
		}
		f.calls.Add(1)
		if s := f.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if ck, err := r.Cookie(CookieName); err == nil {
			switch ck.Value {
			case "good":
				_, _ = w.Write([]byte(`{"id":"u1","email":"u@example.com","is_admin":false,"timezone":"UTC"}`))
				return
			case "boss":
				_, _ = w.Write([]byte(`{"id":"u2","email":"boss@example.com","is_admin":true,"timezone":"UTC"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") == "Bearer ak_good" {
			_, _ = w.Write([]byte(`{"id":"u1","email":"u@example.com","is_admin":false,"timezone":"UTC","key":{"id":"k1","name":"cli"}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(f.Close)
	return f
}

// echoUser records what the handler behind the middleware saw.
func echoUser(got **User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = UserFrom(r.Context())
	})
}

func req(cookie, bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: cookie})
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func TestMiddlewareIdentifies(t *testing.T) {
	f := newFake(t)
	for _, tc := range []struct {
		name           string
		cookie, bearer string
		wantID, wantK  string
		wantCalls      int32
	}{
		{"cookie", "good", "", "u1", "", 1},
		{"api key", "", "ak_good", "u1", "k1", 1},
		{"cookie beats key", "boss", "ak_good", "u2", "", 1},
		{"bad cookie", "nope", "", "", "", 1},
		{"no credential, no call", "", "", "", "", 0},
		{"non-voodoo bearer not forwarded", "", "eyJhbGciOi", "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(f.URL)
			before := f.calls.Load()
			var got *User
			c.Middleware(echoUser(&got)).ServeHTTP(httptest.NewRecorder(), req(tc.cookie, tc.bearer))
			if n := f.calls.Load() - before; n != tc.wantCalls {
				t.Errorf("calls = %d, want %d", n, tc.wantCalls)
			}
			if tc.wantID == "" {
				if got != nil {
					t.Fatalf("user = %+v, want nil", got)
				}
				return
			}
			if got == nil || got.ID != tc.wantID {
				t.Fatalf("user = %+v, want id %s", got, tc.wantID)
			}
			if (got.Key != nil) != (tc.wantK != "") || (got.Key != nil && got.Key.ID != tc.wantK) {
				t.Errorf("key = %+v, want %q", got.Key, tc.wantK)
			}
		})
	}
}

func TestCache(t *testing.T) {
	f := newFake(t)
	c := New(f.URL)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	h := c.Middleware(http.NotFoundHandler())

	for range 3 {
		h.ServeHTTP(httptest.NewRecorder(), req("good", ""))
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("calls within TTL = %d, want 1", n)
	}
	now = now.Add(59 * time.Second)
	h.ServeHTTP(httptest.NewRecorder(), req("good", ""))
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("calls at 59s = %d, want 1", n)
	}
	now = now.Add(2 * time.Second)
	h.ServeHTTP(httptest.NewRecorder(), req("good", ""))
	if n := f.calls.Load(); n != 2 {
		t.Fatalf("calls after TTL = %d, want 2", n)
	}
	for k := range c.cache {
		for _, raw := range []string{"good", "cookie:good"} {
			if string(k[:]) == raw {
				t.Fatal("cache keyed by raw credential")
			}
		}
	}
}

func TestFailuresNotCached(t *testing.T) {
	f := newFake(t)
	c := New(f.URL)
	h := c.Middleware(http.NotFoundHandler())

	// 401s are not cached: a later sign-in must take effect at once.
	h.ServeHTTP(httptest.NewRecorder(), req("nope", ""))
	h.ServeHTTP(httptest.NewRecorder(), req("nope", ""))
	if n := f.calls.Load(); n != 2 {
		t.Errorf("401 calls = %d, want 2", n)
	}

	// Outage is not cached, and the recovery is seen on the next request.
	f.status.Store(http.StatusBadGateway)
	h.ServeHTTP(httptest.NewRecorder(), req("good", ""))
	f.status.Store(0)
	var got *User
	c.Middleware(echoUser(&got)).ServeHTTP(httptest.NewRecorder(), req("good", ""))
	if got == nil || f.calls.Load() != 4 {
		t.Errorf("after recovery user = %v calls = %d, want user and 4", got, f.calls.Load())
	}
}

func TestCacheBounded(t *testing.T) {
	f := newFake(t)
	c := New(f.URL)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for i := range maxEntries {
		c.cache[[32]byte{byte(i), byte(i >> 8)}] = cacheEntry{&User{ID: "x"}, now.Add(time.Second)}
	}
	c.Middleware(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), req("good", ""))
	if len(c.cache) != maxEntries {
		t.Fatalf("live cache = %d, want capped at %d", len(c.cache), maxEntries)
	}
	now = now.Add(2 * time.Second) // the filler has expired; "good" has not
	c.Middleware(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), req("boss", ""))
	if len(c.cache) > 2 {
		t.Fatalf("expired entries kept: %d", len(c.cache))
	}
}

func TestRequire(t *testing.T) {
	f := newFake(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	browser := func(method, cookie string) *http.Request {
		r := httptest.NewRequest(method, "/admin?x=1", nil)
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: cookie})
		}
		return r
	}
	for _, tc := range []struct {
		name   string
		admin  bool
		r      *http.Request
		status int
	}{
		{"user ok", false, browser("GET", "good"), http.StatusTeapot},
		{"browser redirected", false, browser("GET", ""), http.StatusFound},
		{"browser bad cookie redirected", false, browser("GET", "nope"), http.StatusFound},
		{"browser post 401", false, browser("POST", ""), http.StatusUnauthorized},
		{"api 401", false, req("", "ak_bad"), http.StatusUnauthorized},
		{"api key ok", false, req("", "ak_good"), http.StatusTeapot},
		{"admin ok", true, browser("GET", "boss"), http.StatusTeapot},
		{"non-admin 403", true, browser("GET", "good"), http.StatusForbidden},
		{"admin anonymous redirected", true, browser("GET", ""), http.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(f.URL)
			c.AppURL = "https://app.example.com/"
			inner := c.RequireUser(ok)
			if tc.admin {
				inner = c.RequireAdmin(ok)
			}
			rec := httptest.NewRecorder()
			c.Middleware(inner).ServeHTTP(rec, tc.r)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if rec.Code == http.StatusFound {
				want := f.URL + "/login?next=" + url.QueryEscape("https://app.example.com/admin?x=1")
				if got := rec.Header().Get("Location"); got != want {
					t.Errorf("Location = %q, want %q", got, want)
				}
			}
		})
	}
}

// LoginURL falls back to the Host header only when AppURL is unset (dev).
func TestLoginURLWithoutAppURL(t *testing.T) {
	c := New("http://localhost:8080/")
	r := httptest.NewRequest(http.MethodGet, "http://localhost:8081/a?b=c", nil)
	want := "http://localhost:8080/login?next=" + url.QueryEscape("http://localhost:8081/a?b=c")
	if got := c.LoginURL(r); got != want {
		t.Errorf("LoginURL = %q, want %q", got, want)
	}
	if got := c.LogoutURL(); got != "http://localhost:8080/logout" {
		t.Errorf("LogoutURL = %q", got)
	}
}

func TestUnavailableFailsClosed(t *testing.T) {
	f := newFake(t)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close() // connection refused from here on

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for name, setup := range map[string]func() *Client{
		"unreachable": func() *Client { return New(downURL) },
		"5xx": func() *Client {
			f.status.Store(http.StatusInternalServerError)
			t.Cleanup(func() { f.status.Store(0) })
			return New(f.URL)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := setup()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "text/html")
			r.AddCookie(&http.Cookie{Name: CookieName, Value: "good"})

			// Public page: renders, signed out.
			var got *User
			c.Middleware(echoUser(&got)).ServeHTTP(httptest.NewRecorder(), r)
			if got != nil {
				t.Errorf("user = %+v during outage, want nil", got)
			}
			// Protected page: 503, not a login redirect.
			for _, h := range []http.Handler{c.RequireUser(ok), c.RequireAdmin(ok)} {
				rec := httptest.NewRecorder()
				c.Middleware(h).ServeHTTP(rec, r)
				if rec.Code != http.StatusServiceUnavailable {
					t.Errorf("status = %d, want 503", rec.Code)
				}
			}
			if len(c.cache) != 0 {
				t.Error("outage cached")
			}
		})
	}
}
