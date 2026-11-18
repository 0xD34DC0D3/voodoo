// Package voodooauth is the client side of voodoo's sibling-app contract
// (docs/integration.md) as plain net/http middleware. It is the only Go code
// apps import from voodoo, so it depends on the standard library alone.
//
// Usage:
//
//	auth := voodooauth.New("https://auth.example.com")
//	auth.AppURL = "https://app.example.com" // where login sends users back
//	handler := auth.Middleware(mux)
//	mux.Handle("GET /inbox", auth.RequireUser(inbox))
//	mux.Handle("GET /admin", auth.RequireAdmin(admin))
//
// Middleware only identifies the caller; RequireUser and RequireAdmin enforce.
//
// Failure handling: when voodoo is unreachable or answers 5xx the request
// carries no user, so public pages render as signed out, but RequireUser and
// RequireAdmin answer 503. Redirecting to login would be wrong there: the user
// may be signed in, and the login page is on the server that is down.
package voodooauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CookieName is voodoo's parent-domain session cookie, the one sibling apps
// receive and forward to /me.
const CookieName = "voodoo_session"

const (
	// cacheTTL bounds how long a revoked session or key keeps working here.
	cacheTTL = 60 * time.Second
	// maxEntries caps memory: one entry per distinct live credential.
	maxEntries = 10000
	// meTimeout keeps a slow voodoo from holding every request hostage.
	meTimeout = 5 * time.Second
	// maxMeBody: /me answers a few hundred bytes; anything bigger is wrong.
	maxMeBody = 64 << 10
)

// User is the identity /me returns. Use ID verbatim as the app's user id.
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	Timezone string `json:"timezone"`
	// Key is set when the request authenticated with an API key, nil for a
	// session cookie.
	Key *Key `json:"key,omitempty"`
}

// Key identifies the API key a request used.
type Key struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Client checks credentials against one voodoo server and caches positive
// answers. Set fields before serving; it is safe for concurrent use after.
type Client struct {
	baseURL string

	// AppURL is this app's external origin (e.g. "https://app.example.com"),
	// used to build the absolute next= URL voodoo returns users to. Leave it
	// empty only in local development: the request's Host header is then
	// trusted, and in production that header is attacker-controlled.
	AppURL string

	// HTTP makes the /me calls. Its own timeout, if any, applies on top of
	// the 5 s per-call limit.
	HTTP *http.Client

	mu    sync.Mutex
	cache map[[sha256.Size]byte]cacheEntry
	now   func() time.Time // tests move the clock
}

type cacheEntry struct {
	user    *User
	expires time.Time
}

// New returns a client for the voodoo server at baseURL
// (e.g. "https://auth.example.com").
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    http.DefaultClient,
		cache:   make(map[[sha256.Size]byte]cacheEntry),
		now:     time.Now,
	}
}

type ctxKey struct{}

// state is what Middleware learned about the request.
type state struct {
	user        *User
	unavailable bool // voodoo could not answer; Require* must not treat as signed out
}

// UserFrom returns the signed-in user, or nil for anonymous requests and
// requests that did not pass through Middleware.
func UserFrom(ctx context.Context) *User {
	s, _ := ctx.Value(ctxKey{}).(state)
	return s.user
}

// Middleware identifies the caller from the voodoo_session cookie or an
// "Authorization: Bearer ak_..." API key (the cookie wins, as at voodoo) and
// puts the user on the request context. It never rejects a request.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind, cred := credential(r)
		if cred == "" {
			next.ServeHTTP(w, r) // anonymous; nothing to ask voodoo
			return
		}
		u, err := c.lookup(r.Context(), kind, cred)
		if err != nil {
			// Never log the credential; the error names only the endpoint.
			slog.Warn("voodooauth: /me failed", "err", err)
		}
		st := state{user: u, unavailable: err != nil}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, st)))
	})
}

// RequireUser lets signed-in requests through. Otherwise a browser page load
// is redirected to voodoo's login and everything else gets 401. If voodoo was
// unreachable it answers 503 instead (see the package doc).
func (c *Client) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, _ := r.Context().Value(ctxKey{}).(state)
		switch {
		case st.user != nil:
			next.ServeHTTP(w, r)
		case st.unavailable:
			http.Error(w, "authentication service unavailable", http.StatusServiceUnavailable)
		case isBrowserPageLoad(r):
			http.Redirect(w, r, c.LoginURL(r), http.StatusFound)
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	})
}

// RequireAdmin is RequireUser plus voodoo's is_admin; other users get 403.
func (c *Client) RequireAdmin(next http.Handler) http.Handler {
	return c.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !UserFrom(r.Context()).IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// LoginURL is voodoo's login page with next= set to r's absolute URL, so the
// user lands back on the same page after signing in.
func (c *Client) LoginURL(r *http.Request) string {
	origin := strings.TrimRight(c.AppURL, "/")
	if origin == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin = scheme + "://" + r.Host
	}
	return c.baseURL + "/login?next=" + url.QueryEscape(origin+r.URL.RequestURI())
}

// LogoutURL is where a logout form posts. voodoo accepts the post from
// sibling hosts and ends the session for every app at once.
func (c *Client) LogoutURL() string { return c.baseURL + "/logout" }

// credential picks the cookie over the API key, matching voodoo's own order so
// both sides agree on who the caller is.
func credential(r *http.Request) (kind, value string) {
	if ck, err := r.Cookie(CookieName); err == nil && ck.Value != "" {
		return "cookie", ck.Value
	}
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") && strings.HasPrefix(h[7:], "ak_") {
		// Only voodoo API keys are forwarded: any other bearer token was
		// meant for someone else and must not be sent to voodoo.
		return "bearer", h[7:]
	}
	return "", ""
}

// isBrowserPageLoad: only a page navigation can usefully follow a redirect to
// a login form and come back; API clients and form posts get a plain 401.
func isBrowserPageLoad(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// lookup returns the user (nil for 401) or an error when voodoo could not
// give an answer. Only users are cached: a cached 401 would keep a user who
// just signed in locked out, and a cached failure would outlive the outage.
func (c *Client) lookup(ctx context.Context, kind, cred string) (*User, error) {
	// Keyed by a digest so a heap dump holds no usable credential.
	key := sha256.Sum256([]byte(kind + ":" + cred))
	now := c.now()

	c.mu.Lock()
	e, ok := c.cache[key]
	c.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.user, nil
	}

	u, err := c.fetchMe(ctx, kind, cred)
	if err != nil || u == nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= maxEntries {
		for k, e := range c.cache {
			if !now.Before(e.expires) {
				delete(c.cache, k)
			}
		}
		// Still full of live entries: drop an arbitrary one rather than grow.
		for k := range c.cache {
			if len(c.cache) < maxEntries {
				break
			}
			delete(c.cache, k)
		}
	}
	c.cache[key] = cacheEntry{user: u, expires: now.Add(cacheTTL)}
	return u, nil
}

type statusError struct{ code int }

func (e statusError) Error() string { return "voodoo /me answered " + http.StatusText(e.code) }

func (c *Client) fetchMe(ctx context.Context, kind, cred string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, meTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/me", nil)
	if err != nil {
		return nil, err
	}
	if kind == "cookie" {
		req.AddCookie(&http.Cookie{Name: CookieName, Value: cred})
	} else {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var u User
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxMeBody)).Decode(&u); err != nil {
			return nil, err
		}
		if u.ID == "" {
			return nil, errors.New("voodoo /me: response has no id") // malformed, not a sign-out
		}
		return &u, nil
	case http.StatusUnauthorized:
		return nil, nil
	default:
		// Anything else (5xx, a proxy's 4xx) is not voodoo saying "signed out".
		return nil, statusError{resp.StatusCode}
	}
}
