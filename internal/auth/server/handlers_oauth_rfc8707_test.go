package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
)

// RFC 8707 resource indicators, end to end.
//
// The property under test throughout this file is one sentence: a token minted for
// one resource server must be useless at any other. Everything else — requiring
// the parameter, canonicalizing it, recording it, refusing to widen it, checking
// it at verification — exists only to make that sentence true, so each test below
// names which link in that chain it holds down.

// Link 1: the audience must be stated. A request with no resource cannot produce
// an audience-bound token, so it must not produce a token at all.
func TestAuthorizeRequiresResource(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	q := authzQuery(clientID)
	q.Del("resource")

	got := redirectQuery(t, e.get(t, "/authorize?"+q.Encode(), ck))
	// Absent is a malformed request rather than a bad target: there is no target
	// to have an opinion about.
	if got.Get("error") != oauth.ErrCodeInvalidRequest {
		t.Fatalf("error = %q, want %q", got.Get("error"), oauth.ErrCodeInvalidRequest)
	}
	if got.Get("code") != "" {
		t.Fatal("issued a code with no audience")
	}
}

// Link 2: the audience must be one this deployment serves, and there must be
// exactly one of it.
func TestAuthorizeRejectsBadResources(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	cases := []struct {
		name     string
		resource []string
		wantErr  string
	}{
		{"foreign host", []string{"https://evil.example.com/mcp"}, oauth.ErrCodeInvalidTarget},
		{"fragment", []string{"http://localhost:8081/mcp#x"}, oauth.ErrCodeInvalidTarget},
		{"relative", []string{"/mcp"}, oauth.ErrCodeInvalidTarget},
		{"not a uri", []string{"://"}, oauth.ErrCodeInvalidTarget},
		{"urn", []string{"urn:example:mcp"}, oauth.ErrCodeInvalidTarget},
		{"userinfo", []string{"http://u:p@localhost:8081/mcp"}, oauth.ErrCodeInvalidTarget},
		// A multi-audience token would be broader than the request that created it.
		{"two resources", []string{testResource, testResourceOther}, oauth.ErrCodeInvalidTarget},
		{"empty value", []string{""}, oauth.ErrCodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := authzQuery(clientID)
			q["resource"] = tc.resource

			got := redirectQuery(t, e.get(t, "/authorize?"+q.Encode(), ck))
			if got.Get("error") != tc.wantErr {
				t.Fatalf("error = %q, want %q", got.Get("error"), tc.wantErr)
			}
			if got.Get("code") != "" {
				t.Fatal("issued a code for a rejected audience")
			}
		})
	}
}

// Link 3: the audience recorded on the token is the canonical form, so equivalent
// spellings of one resource cannot become two audiences — or worse, let a resource
// server's own spelling fail to match the token it was handed.
func TestResourceIsCanonicalizedOnGrant(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID := e.mkClient(t)

	// Ask with a deliberately noisy spelling: uppercase host, explicit default
	// port, trailing slash.
	q := authzQuery(clientID)
	q.Set("resource", "http://LOCALHOST:80/mcp")
	code := codeFromRedirect(t, e.consent(t, ck, q, "approve"))

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusOK {
		t.Fatalf("/token status=%d body=%s", rr.Code, rr.Body.String())
	}

	var stored string
	if err := e.db.QueryRow(
		`SELECT resource FROM oauth_tokens WHERE user_id = ? AND kind = 'access'`, userID,
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "http://localhost/mcp" {
		t.Fatalf("stored audience = %q, want the canonical form", stored)
	}

	// And the canonical form is what a resource server must present to verify.
	var tb tokenBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &tb); err != nil {
		t.Fatal(err)
	}
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, "http://localhost/mcp"); !resp.Active {
		t.Fatal("canonical audience did not verify")
	}
	// Any spelling that differs only in what canonicalization folds — scheme case,
	// host case, default port — still verifies, because both sides get canonicalized.
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, "HTTP://LocalHost:80/mcp"); !resp.Active {
		t.Fatal("an equivalent spelling of the audience failed to verify")
	}
	// A trailing slash is *not* folded, and that is deliberate: "/mcp" and "/mcp/"
	// are different paths in RFC 3986, and guessing that a server means the same
	// thing by both is the kind of normalization that quietly widens an audience.
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, "http://localhost/mcp/"); resp.Active {
		t.Fatal("a trailing-slash variant verified — path normalization must not widen the audience")
	}
}

// Link 4: the token request cannot redirect the audience. If it could, a client
// could obtain consent for one resource and a token for another.
func TestTokenRequestCannotChangeAudience(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	cases := []struct {
		name     string
		resource []string
	}{
		{"a different valid audience", []string{testResourceOther}},
		{"a foreign audience", []string{"https://evil.example.com/mcp"}},
		{"two audiences", []string{testResource, testResourceOther}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))
			form := redeemForm(clientID, code)
			form["resource"] = tc.resource

			rr := e.postForm(t, "/token", form)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
			}
			if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidTarget {
				t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidTarget)
			}
		})
	}
}

// RFC 8707 §2.2 makes resource optional on the token request. Omitting it inherits
// the audience from the authorization request rather than clearing it.
func TestTokenRequestMayOmitResource(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var tb tokenBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &tb); err != nil {
		t.Fatal(err)
	}

	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); !resp.Active {
		t.Fatal("token did not inherit the authorized audience")
	}
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResourceOther); resp.Active {
		t.Fatal("omitting resource produced a token valid at any audience")
	}
}

// Link 5, the one that makes the rest matter: verification enforces the audience.
// This is the cross-app replay the whole mechanism exists to stop.
func TestTokenIsUselessAtAnotherResource(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	_, tb := e.grantTokens(t, ck)

	rr, resp := e.introspect(t, apiKey, tb.AccessToken, testResource)
	if rr.Code != http.StatusOK || !resp.Active {
		t.Fatalf("token should verify at its own audience: status=%d active=%v", rr.Code, resp.Active)
	}
	if resp.Aud != testResource {
		t.Fatalf("aud = %q, want %q", resp.Aud, testResource)
	}

	// The same live token, presented by a different resource server.
	rr, resp = e.introspect(t, apiKey, tb.AccessToken, testResourceOther)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 with active:false", rr.Code)
	}
	if resp.Active {
		t.Fatal("a token minted for one resource verified at another")
	}
	// An inactive answer must carry nothing else: it cannot become an oracle for
	// who the token belongs to or what it was for.
	if resp.Sub != "" || resp.Email != "" || resp.Aud != "" || resp.ClientID != "" || resp.Scope != "" {
		t.Fatalf("inactive response leaked token details: %+v", resp)
	}
}

// A resource server that fails to identify itself gets a loud error, not a
// permissive default. This is the difference between a mechanism and a suggestion.
func TestIntrospectRequiresResource(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	_, tb := e.grantTokens(t, ck)

	rr, _ := e.introspect(t, apiKey, tb.AccessToken, "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 — omitting resource must fail, not default open",
			rr.Code, rr.Body.String())
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidRequest {
		t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidRequest)
	}
}

func TestIntrospectRejectsUnservedResource(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	_, tb := e.grantTokens(t, ck)

	rr, _ := e.introspect(t, apiKey, tb.AccessToken, "https://evil.example.com/mcp")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidTarget {
		t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidTarget)
	}
}

func TestIntrospectActiveResponseShape(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, tb := e.grantTokens(t, ck)

	rr, resp := e.introspect(t, apiKey, tb.AccessToken, testResource)
	if !resp.Active {
		t.Fatalf("not active: %s", rr.Body.String())
	}
	if resp.Sub != userID {
		t.Fatalf("sub = %q, want %q", resp.Sub, userID)
	}
	if resp.ClientID != clientID {
		t.Fatalf("client_id = %q, want %q", resp.ClientID, clientID)
	}
	if resp.Email != "alice@example.com" || resp.Username != "alice@example.com" {
		t.Fatalf("identity fields wrong: %+v", resp)
	}
	if resp.Scope != oauth.ScopeIdentity {
		t.Fatalf("scope = %q", resp.Scope)
	}
	if resp.TokenType != "Bearer" || resp.Exp == 0 || resp.Iat == 0 {
		t.Fatalf("token metadata wrong: %+v", resp)
	}
	if resp.Timezone == "" {
		t.Fatal("timezone missing — a resource server needs the same fields /me returns")
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

// Access tokens are deliberately not a credential at /me. /me has no way to learn
// who is calling, so it has no way to check an audience — accepting one there
// would reintroduce exactly the replay this file is about.
func TestAccessTokenIsNotAcceptedAtMe(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	_, tb := e.grantTokens(t, ck)

	for _, token := range []string{tb.AccessToken, tb.RefreshToken} {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
			t.Fatalf("/me with %s… status=%d, want 401", token[:4], rr.Code)
		}
	}
}

// A refresh token must never be accepted as an access token, or leaking one to a
// resource server would be as bad as leaking it to the token endpoint.
func TestRefreshTokenDoesNotIntrospectAsActive(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	_, tb := e.grantTokens(t, ck)

	if _, resp := e.introspect(t, apiKey, tb.RefreshToken, testResource); resp.Active {
		t.Fatal("a refresh token verified as an access token")
	}
}

func TestIntrospectInactiveCases(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)

	t.Run("unknown token", func(t *testing.T) {
		if _, resp := e.introspect(t, apiKey, "vat_nonexistent", testResource); resp.Active {
			t.Fatal("unknown token reported active")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		_, tb := e.grantTokens(t, ck)
		e.expireToken(t, tb.AccessToken)
		if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
			t.Fatal("expired token reported active")
		}
	})

	t.Run("user disabled after issuance", func(t *testing.T) {
		bobID, bobCk := e.userCookie(t, "bob@example.com")
		_, tb := e.grantTokens(t, bobCk)

		if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); !resp.Active {
			t.Fatal("token should start out active")
		}
		if _, err := e.db.Exec(`UPDATE users SET disabled_at = CURRENT_TIMESTAMP WHERE id = ?`, bobID); err != nil {
			t.Fatal(err)
		}
		if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
			t.Fatal("a disabled user's token still verified")
		}
	})
}

// Introspection is for resource servers, which authenticate. An anonymous caller
// must not be able to test token strings against it.
func TestIntrospectRequiresCallerAuth(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	_, tb := e.grantTokens(t, ck)

	rr := e.postForm(t, "/introspect", url.Values{
		"token":    {tb.AccessToken},
		"resource": {testResource},
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rr.Code)
	}
}

// In production the localhost exemption is gone, so only https hosts inside the
// parent domain are valid audiences. This is the same trust boundary the session
// cookie uses, and this test pins the two together.
func TestResourcePolicyInProduction(t *testing.T) {
	e := setup(t)
	e.srv.cfg.CookieSecure = true
	e.srv.cfg.CookieDomain = ".example.com"

	cases := []struct {
		resource string
		want     bool
	}{
		{"https://app.example.com/mcp", true},
		{"https://example.com/mcp", true},
		{"https://deep.nested.example.com/mcp", true},
		{"http://app.example.com/mcp", false},   // plaintext
		{"https://example.com.evil.com", false}, // suffix trickery
		{"https://notexample.com/mcp", false},
		{"http://localhost:8081/mcp", false}, // no dev exemption in prod
	}
	for _, tc := range cases {
		canonical, err := oauth.CanonicalResource(tc.resource)
		if err != nil {
			t.Fatalf("CanonicalResource(%q): %v", tc.resource, err)
		}
		if got := e.srv.resourceAllowed(canonical); got != tc.want {
			t.Fatalf("resourceAllowed(%q) = %v, want %v", canonical, got, tc.want)
		}
	}
}

// The consent screen must show the audience. A user approving a connection needs
// to see which app the token will work at, or "approve" means nothing specific.
func TestConsentScreenNamesTheAudience(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	q := authzQuery(clientID)
	q.Set("resource", testResourceOther)
	rr := e.get(t, "/authorize?"+q.Encode(), ck)

	if !strings.Contains(rr.Body.String(), testResourceOther) {
		t.Fatalf("consent page does not name the audience %q", testResourceOther)
	}
}
