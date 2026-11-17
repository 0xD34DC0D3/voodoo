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

func TestOAuthMetadata(t *testing.T) {
	e := setup(t)
	e.srv.cfg.BaseURL = "https://voodoo.example.com/"

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		rr := e.do(t, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rr.Code)
		}
		var md asMetadata
		if err := json.Unmarshal(rr.Body.Bytes(), &md); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
		// The trailing slash on BaseURL must not survive into the issuer: clients
		// compare it byte-for-byte against the URL they fetched (RFC 8414 §3.3).
		if md.Issuer != "https://voodoo.example.com" {
			t.Fatalf("%s issuer = %q", path, md.Issuer)
		}
		if md.AuthorizationEndpoint != "https://voodoo.example.com/authorize" {
			t.Fatalf("%s authorization_endpoint = %q", path, md.AuthorizationEndpoint)
		}
		// PKCE-only, code-only, public-clients-only. Advertising anything else
		// would promise a flow this server refuses to run.
		if len(md.CodeChallengeMethodsSupported) != 1 || md.CodeChallengeMethodsSupported[0] != oauth.MethodS256 {
			t.Fatalf("%s code_challenge_methods_supported = %v", path, md.CodeChallengeMethodsSupported)
		}
		if len(md.ResponseTypesSupported) != 1 || md.ResponseTypesSupported[0] != "code" {
			t.Fatalf("%s response_types_supported = %v", path, md.ResponseTypesSupported)
		}
		if len(md.TokenEndpointAuthMethodsSupported) != 1 || md.TokenEndpointAuthMethodsSupported[0] != "none" {
			t.Fatalf("%s token_endpoint_auth_methods_supported = %v", path, md.TokenEndpointAuthMethodsSupported)
		}
		if !md.AuthorizationResponseIssParamSupported {
			t.Fatalf("%s should advertise RFC 9207 iss support", path)
		}
	}
}

func TestOAuthMetadataFallsBackToRequestHost(t *testing.T) {
	e := setup(t)
	e.srv.cfg.BaseURL = ""

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	req.Host = "localhost:8080"
	rr := e.do(t, req)

	var md asMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md.Issuer != "http://localhost:8080" {
		t.Fatalf("issuer = %q, want the request's own origin", md.Issuer)
	}
}

func TestRegisterPublicClient(t *testing.T) {
	e := setup(t)

	rr := e.postJSON(t, "/register", `{
		"client_name": "Example MCP Client",
		"redirect_uris": ["http://127.0.0.1:49152/callback"],
		"client_uri": "https://example.com"
	}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var resp registerResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.ClientID, oauth.ClientIDPrefix) {
		t.Fatalf("client_id = %q", resp.ClientID)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Fatalf("token_endpoint_auth_method = %q, want none", resp.TokenEndpointAuthMethod)
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Fatal("client_id_issued_at not set")
	}
	// No secret exists to leak, and the response must not imply one does.
	if strings.Contains(rr.Body.String(), "client_secret") {
		t.Fatalf("registration response mentions a client secret: %s", rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestRegisterRejections(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"no redirect_uris", `{"client_name":"x"}`},
		{"empty redirect_uris", `{"redirect_uris":[]}`},
		{"plaintext http on a routable host", `{"redirect_uris":["http://example.com/cb"]}`},
		{"redirect with a fragment", `{"redirect_uris":["https://example.com/cb#f"]}`},
		{"relative redirect", `{"redirect_uris":["/cb"]}`},
		{"not json", `not json at all`},
		{"secret-based client auth", `{"redirect_uris":["https://e.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}`},
		{"implicit flow", `{"redirect_uris":["https://e.com/cb"],"response_types":["token"]}`},
		{"password grant", `{"redirect_uris":["https://e.com/cb"],"grant_types":["password"]}`},
		{"javascript client_uri", `{"redirect_uris":["https://e.com/cb"],"client_uri":"javascript:alert(1)"}`},
		{"overlong client_name", `{"redirect_uris":["https://e.com/cb"],"client_name":"` + strings.Repeat("n", 200) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			rr := e.postJSON(t, "/register", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
			}
			if code := oauthErrorOf(t, rr).Code; code == "" {
				t.Fatalf("no error code in body: %s", rr.Body.String())
			}
		})
	}
}

func TestRegisterRateLimited(t *testing.T) {
	e := setup(t)
	const body = `{"redirect_uris":["https://example.com/cb"]}`

	// The burst is 5; the sixth registration from one address must be refused, or
	// an unauthenticated endpoint that writes rows has no ceiling at all.
	for i := range 5 {
		if rr := e.postJSON(t, "/register", body); rr.Code != http.StatusCreated {
			t.Fatalf("registration %d status=%d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	rr := e.postJSON(t, "/register", body)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", rr.Code)
	}
}

func TestAuthorizeRequiresLogin(t *testing.T) {
	e := setup(t)
	clientID := e.mkClient(t)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+authzQuery(clientID).Encode(), nil)
	rr := e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d, want a redirect to login", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("Location = %q, want /login?next=…", loc)
	}
	// The whole authorization request must survive the login round trip, or the
	// user logs in and lands nowhere useful.
	next, err := url.QueryUnescape(strings.TrimPrefix(loc, "/login?next="))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(next, "/authorize?") || !strings.Contains(next, "code_challenge") {
		t.Fatalf("next = %q, want the full authorize request", next)
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	q := authzQuery(clientID)

	// The consent screen must name what is being approved — an approval the user
	// cannot read is not consent.
	page := e.get(t, "/authorize?"+q.Encode(), ck)
	body := page.Body.String()
	for _, want := range []string{"Test Client", testResource, "alice@example.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("consent page does not mention %q", want)
		}
	}

	rr := e.consent(t, ck, q, "approve")
	got := redirectQuery(t, rr)
	if got.Get("code") == "" {
		t.Fatalf("no code in %v", got)
	}
	if got.Get("state") != "opaque-state" {
		t.Fatalf("state = %q, want it echoed back verbatim", got.Get("state"))
	}
	if got.Get("iss") == "" {
		t.Fatal("no iss in the authorization response (RFC 9207)")
	}

	tb := e.redeem(t, clientID, got.Get("code"))
	if !strings.HasPrefix(tb.AccessToken, oauth.AccessTokenPrefix) {
		t.Fatalf("access_token = %q", tb.AccessToken)
	}
	if !strings.HasPrefix(tb.RefreshToken, oauth.RefreshTokenPrefix) {
		t.Fatalf("refresh_token = %q", tb.RefreshToken)
	}
	if tb.TokenType != "Bearer" {
		t.Fatalf("token_type = %q", tb.TokenType)
	}
	if tb.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d", tb.ExpiresIn)
	}
	// RFC 6749 §3.3: the granted scope is always stated, so a client never has to
	// infer it.
	if tb.Scope != oauth.ScopeIdentity {
		t.Fatalf("scope = %q, want %q", tb.Scope, oauth.ScopeIdentity)
	}
}

func TestAuthorizeDenyReturnsAccessDenied(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	got := redirectQuery(t, e.consent(t, ck, authzQuery(clientID), "deny"))
	if got.Get("error") != oauth.ErrCodeAccessDenied {
		t.Fatalf("error = %q, want %q", got.Get("error"), oauth.ErrCodeAccessDenied)
	}
	if got.Get("code") != "" {
		t.Fatal("a denied request must not produce a code")
	}
	if got.Get("state") != "opaque-state" {
		t.Fatalf("state = %q, want it echoed on the error too", got.Get("state"))
	}
}

// An untrusted client_id or redirect_uri must never be redirected to. If it were,
// /authorize would be an open redirector on voodoo's own domain.
func TestAuthorizeRefusesToRedirectUntrustedTargets(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	cases := []struct {
		name string
		mut  func(url.Values)
	}{
		{"unknown client", func(q url.Values) { q.Set("client_id", "vc_nope") }},
		{"missing client", func(q url.Values) { q.Del("client_id") }},
		{"unregistered redirect_uri", func(q url.Values) { q.Set("redirect_uri", "https://evil.example.com/cb") }},
		{"missing redirect_uri", func(q url.Values) { q.Del("redirect_uri") }},
		{"redirect_uri with an extra path segment", func(q url.Values) { q.Set("redirect_uri", testRedirectURI+"/x") }},
		{"redirect_uri with an appended query", func(q url.Values) { q.Set("redirect_uri", testRedirectURI+"?x=1") }},
		{"duplicated client_id", func(q url.Values) { q.Add("client_id", "vc_other") }},
		{"duplicated redirect_uri", func(q url.Values) { q.Add("redirect_uri", "https://evil.example.com/cb") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := authzQuery(clientID)
			tc.mut(q)
			assertAuthzErrorPage(t, e.get(t, "/authorize?"+q.Encode(), ck))
			// The consent POST takes the same path.
			assertAuthzErrorPage(t, e.postForm(t, "/authorize", consentForm(q, "x", "approve"), ck))
		})
	}
}

func assertAuthzErrorPage(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 rendered in place", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("must not redirect, got Location=%q", loc)
	}
	if !strings.Contains(rr.Body.String(), "Authorization error") {
		t.Fatalf("want the error page, got %s", rr.Body.String())
	}
}

// Once the redirect target is verified, protocol errors go back to the client the
// way the spec says — as a redirect carrying error and state.
func TestAuthorizeRedirectsProtocolErrors(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	cases := []struct {
		name     string
		mut      func(url.Values)
		wantCode string
	}{
		{"missing PKCE", func(q url.Values) {
			q.Del("code_challenge")
			q.Del("code_challenge_method")
		}, oauth.ErrCodeInvalidRequest},
		{"plain PKCE is refused", func(q url.Values) {
			q.Set("code_challenge_method", "plain")
			q.Set("code_challenge", testVerifier)
		}, oauth.ErrCodeInvalidRequest},
		{"malformed challenge", func(q url.Values) { q.Set("code_challenge", "too-short") }, oauth.ErrCodeInvalidRequest},
		{"implicit flow", func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		{"unsupported scope", func(q url.Values) { q.Set("scope", "openid profile") }, oauth.ErrCodeInvalidScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := authzQuery(clientID)
			tc.mut(q)
			got := redirectQuery(t, e.get(t, "/authorize?"+q.Encode(), ck))

			if got.Get("error") != tc.wantCode {
				t.Fatalf("error = %q, want %q", got.Get("error"), tc.wantCode)
			}
			if got.Get("state") != "opaque-state" {
				t.Fatalf("state = %q, want it echoed", got.Get("state"))
			}
			if got.Get("code") != "" {
				t.Fatal("a rejected request must not produce a code")
			}
		})
	}
}

func TestConsentRequiresCSRFToken(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	q := authzQuery(clientID)

	approve := func(csrf string) *httptest.ResponseRecorder {
		return e.postForm(t, "/authorize", consentForm(q, csrf, "approve"), ck)
	}

	// The params the real page was rendered with, needed to construct the
	// deliberately-wrong tokens below.
	shown := authzParams{
		ClientID: clientID, RedirectURI: testRedirectURI, Resource: testResource,
		Scope: oauth.ScopeIdentity, Challenge: oauth.ChallengeFromVerifier(testVerifier),
	}
	for _, tc := range []struct{ name, csrf string }{
		{"absent", ""},
		{"wrong", "not-the-token"},
		{"another session's", consentToken("some-other-session-id", shown)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := approve(tc.csrf)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400", rr.Code)
			}
			if loc := rr.Header().Get("Location"); loc != "" {
				t.Fatalf("must not mint a code, got Location=%q", loc)
			}
		})
	}

	// The real token from this session still works, so the check is not simply
	// refusing everything.
	if rr := approve(e.consentCSRF(t, ck, q)); rr.Code != http.StatusFound {
		t.Fatalf("valid csrf status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTokenEndpointRejections(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	// A fresh code per subtest: several of these deliberately burn one.
	newCode := func() string {
		return codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))
	}

	cases := []struct {
		name     string
		form     func(code string) url.Values
		wantCode string
	}{
		{"no grant_type", func(string) url.Values { return url.Values{} }, oauth.ErrCodeInvalidRequest},
		{"unsupported grant_type", func(string) url.Values {
			return url.Values{"grant_type": {"client_credentials"}}
		}, oauth.ErrCodeUnsupportedGrantType},
		{"no code", func(string) url.Values {
			return url.Values{"grant_type": {grantAuthorizationCode}, "client_id": {clientID}}
		}, oauth.ErrCodeInvalidRequest},
		{"unknown code", func(string) url.Values {
			return url.Values{
				"grant_type": {grantAuthorizationCode}, "client_id": {clientID},
				"code": {"vac_nope"}, "redirect_uri": {testRedirectURI}, "code_verifier": {testVerifier},
			}
		}, oauth.ErrCodeInvalidGrant},
		{"wrong code_verifier", func(code string) url.Values {
			return url.Values{
				"grant_type": {grantAuthorizationCode}, "client_id": {clientID}, "code": {code},
				"redirect_uri":  {testRedirectURI},
				"code_verifier": {strings.Repeat("z", 64)},
			}
		}, oauth.ErrCodeInvalidGrant},
		{"missing code_verifier", func(code string) url.Values {
			return url.Values{
				"grant_type": {grantAuthorizationCode}, "client_id": {clientID}, "code": {code},
				"redirect_uri": {testRedirectURI},
			}
		}, oauth.ErrCodeInvalidGrant},
		{"mismatched redirect_uri", func(code string) url.Values {
			return url.Values{
				"grant_type": {grantAuthorizationCode}, "client_id": {clientID}, "code": {code},
				"redirect_uri": {"http://127.0.0.1:49152/other"}, "code_verifier": {testVerifier},
			}
		}, oauth.ErrCodeInvalidGrant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := e.postForm(t, "/token", tc.form(newCode()))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
			}
			if got := oauthErrorOf(t, rr).Code; got != tc.wantCode {
				t.Fatalf("error = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

// A code belongs to the client that requested it. Without this check, any client
// that intercepted a code could redeem it as itself.
func TestCodeIsBoundToItsClient(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	victim := e.mkClient(t)
	attacker := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(victim), "approve"))

	rr := e.postForm(t, "/token", redeemForm(attacker, code))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidGrant {
		t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidGrant)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	e.redeem(t, clientID, code) // first use succeeds

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidGrant {
		t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidGrant)
	}
}

// A failed PKCE check consumes the code too. Leaving it live would let an attacker
// who holds a code keep guessing verifiers against it.
func TestFailedPKCEBurnsTheCode(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	bad := e.postForm(t, "/token", url.Values{
		"grant_type": {grantAuthorizationCode}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("z", 64)},
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad verifier status=%d", bad.Code)
	}

	good := e.postForm(t, "/token", redeemForm(clientID, code))
	if good.Code != http.StatusBadRequest {
		t.Fatalf("the correct verifier still worked after a failed attempt: status=%d body=%s",
			good.Code, good.Body.String())
	}
}

func TestExpiredCodeRejected(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	if _, err := e.db.Exec(`UPDATE oauth_codes SET expires_at = ? WHERE hash = ?`,
		"2020-01-01 00:00:00", oauth.HashOf(code)); err != nil {
		t.Fatal(err)
	}

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

func TestTokenResponseIsNotCacheable(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store (RFC 6749 §5.1)", got)
	}
}

// Tokens are stored hashed, so a database read cannot be replayed as a credential.
func TestTokensAreStoredHashed(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	_, tb := e.grantTokens(t, ck)

	for _, raw := range []string{tb.AccessToken, tb.RefreshToken} {
		var n int
		if err := e.db.QueryRow(`SELECT COUNT(*) FROM oauth_tokens WHERE hash = ?`, raw).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("token %q… is stored in the clear", raw[:12])
		}
		if ok, _ := e.tokenState(t, raw); !ok {
			t.Fatalf("token %q… is not stored under its hash", raw[:12])
		}
	}
	// Codes get the same treatment.
	var codes int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM oauth_codes WHERE hash LIKE ?`,
		oauth.CodePrefix+"%").Scan(&codes); err != nil {
		t.Fatal(err)
	}
	if codes != 0 {
		t.Fatal("authorization codes are stored in the clear")
	}
}
