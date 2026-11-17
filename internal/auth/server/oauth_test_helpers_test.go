package server

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0xD34DC0D3/voodoo/internal/auth/apikey"
	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

// Shared fixtures for the OAuth tests.
//
// The default test config has CookieSecure=false, which puts resource policy in its
// localhost-permitting mode, so these constants are the audiences a test deployment
// will actually mint tokens for. testResourceOther is a second valid audience, used
// to prove that a token for one is not a token for the other.
const (
	testResource      = "http://localhost:8081/mcp"
	testResourceOther = "http://localhost:8082/mcp"
	testRedirectURI   = "http://127.0.0.1:49152/callback"
	testVerifier      = "test-verifier-0123456789abcdefghijklmnopqrstuvwxyz~-._"
)

// --- Requests ---

func (e *testEnv) get(t *testing.T, path string, ck *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	return e.do(t, req)
}

// postForm issues an application/x-www-form-urlencoded POST, optionally
// authenticated with cookies.
func (e *testEnv) postForm(t *testing.T, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	return e.do(t, req)
}

// postJSON issues an application/json POST.
func (e *testEnv) postJSON(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return e.do(t, req)
}

// --- Actors ---

// userCookie creates a non-admin user and logs them in, which is how nearly every
// OAuth test starts: the flow needs a person at a browser.
func (e *testEnv) userCookie(t *testing.T, email string) (userID string, ck *http.Cookie) {
	t.Helper()
	return e.mkUser(t, email), e.userLoginCookie(t, email)
}

// mkAPIKey mints an API key for userID, as a resource server would hold.
func (e *testEnv) mkAPIKey(t *testing.T, userID string) string {
	t.Helper()
	raw, hash, prefix, err := apikey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.q.CreateApiKey(context.Background(), store.CreateApiKeyParams{
		ID:     ids.NewID(),
		UserID: userID,
		Hash:   hash,
		Prefix: prefix,
		Name:   "resource server",
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

// mkClient registers a client through the real /register endpoint — so the tests
// exercise dynamic registration rather than reaching around it — and returns its
// client_id.
func (e *testEnv) mkClient(t *testing.T, redirectURIs ...string) string {
	t.Helper()
	if len(redirectURIs) == 0 {
		redirectURIs = []string{testRedirectURI}
	}
	body, err := json.Marshal(map[string]any{
		"client_name":   "Test Client",
		"redirect_uris": redirectURIs,
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := e.postJSON(t, "/register", string(body))
	if rr.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if resp.ClientID == "" {
		t.Fatal("register returned no client_id")
	}
	return resp.ClientID
}

// --- Authorization ---

// authzQuery builds a well-formed /authorize query. Tests override single fields to
// isolate exactly one defect at a time.
func authzQuery(clientID string) url.Values {
	return url.Values{
		"response_type":         {responseTypeCode},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {oauth.ChallengeFromVerifier(testVerifier)},
		"code_challenge_method": {oauth.MethodS256},
		"state":                 {"opaque-state"},
		"resource":              {testResource},
	}
}

// consentForm turns an /authorize query into the approval POST body the consent page
// would submit, carrying decision and CSRF alongside the request itself.
func consentForm(q url.Values, csrf, decision string) url.Values {
	form := maps.Clone(q)
	form.Set("csrf", csrf)
	form.Set("decision", decision)
	return form
}

// consent walks the browser half of the flow: GET /authorize to obtain the CSRF
// token, then POST the approval.
func (e *testEnv) consent(t *testing.T, ck *http.Cookie, q url.Values, decision string) *httptest.ResponseRecorder {
	t.Helper()
	return e.postForm(t, "/authorize", consentForm(q, e.consentCSRF(t, ck, q), decision), ck)
}

// consentCSRF fetches the consent page and extracts its CSRF token.
func (e *testEnv) consentCSRF(t *testing.T, ck *http.Cookie, q url.Values) string {
	t.Helper()
	rr := e.get(t, "/authorize?"+q.Encode(), ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /authorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	csrf := extractHiddenInput(rr.Body.String(), "csrf")
	if csrf == "" {
		t.Fatalf("consent page had no csrf field: %s", rr.Body.String())
	}
	return csrf
}

// extractHiddenInput pulls a hidden form field's value out of rendered HTML. Crude,
// but it keeps the tests driving the real page rather than a stand-in for it — if the
// template stops emitting a field, they notice.
func extractHiddenInput(body, name string) string {
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// redirectQuery returns the query parameters of a 302 Location.
func redirectQuery(t *testing.T, rr *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return loc.Query()
}

// codeFromRedirect extracts the authorization code from a 302 Location, failing if
// the response was not a redirect carrying one.
func codeFromRedirect(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	code := redirectQuery(t, rr).Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", rr.Header().Get("Location"))
	}
	return code
}

// --- Tokens ---

type tokenBundle struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// redeemForm is a well-formed authorization_code token request. Negative tests
// override one field so the defect under test is the only thing wrong.
func redeemForm(clientID, code string) url.Values {
	return url.Values{
		"grant_type":    {grantAuthorizationCode},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testVerifier},
	}
}

// redeem exchanges a code for tokens, asserting success.
func (e *testEnv) redeem(t *testing.T, clientID, code string) tokenBundle {
	t.Helper()
	form := redeemForm(clientID, code)
	form.Set("resource", testResource)
	return decodeTokens(t, e.postForm(t, "/token", form))
}

// refresh exchanges a refresh token, returning the raw recorder so callers can
// assert on failures too.
func (e *testEnv) refresh(t *testing.T, clientID, refreshToken string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {grantRefreshToken},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}
	maps.Copy(form, extra)
	return e.postForm(t, "/token", form)
}

func (e *testEnv) refreshOK(t *testing.T, clientID, refreshToken string) tokenBundle {
	t.Helper()
	return decodeTokens(t, e.refresh(t, clientID, refreshToken, nil))
}

func decodeTokens(t *testing.T, rr *httptest.ResponseRecorder) tokenBundle {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("/token status=%d body=%s", rr.Code, rr.Body.String())
	}
	var tb tokenBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &tb); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return tb
}

// grantTokens runs the whole flow — register, consent, redeem — and returns the
// client_id and the resulting tokens.
func (e *testEnv) grantTokens(t *testing.T, ck *http.Cookie) (string, tokenBundle) {
	t.Helper()
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))
	return clientID, e.redeem(t, clientID, code)
}

// introspect calls the introspection endpoint as a resource server would,
// authenticating with an API key.
func (e *testEnv) introspect(t *testing.T, apiKey, token, resource string) (*httptest.ResponseRecorder, introspectResponse) {
	t.Helper()
	form := url.Values{"token": {token}}
	if resource != "" {
		form.Set("resource", resource)
	}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rr := e.do(t, req)

	var resp introspectResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode introspection response: %v", err)
		}
	}
	return rr, resp
}

// --- Assertions on state the API does not expose ---

// oauthErrorOf decodes an RFC 6749 error body.
func oauthErrorOf(t *testing.T, rr *httptest.ResponseRecorder) oauth.ErrorBody {
	t.Helper()
	var body oauth.ErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body (status %d): %v — %s", rr.Code, err, rr.Body.String())
	}
	return body
}

// tokenState reports whether a raw token is stored, and whether it is revoked. Used
// to assert on rotation bookkeeping the API does not expose.
func (e *testEnv) tokenState(t *testing.T, raw string) (exists, revoked bool) {
	t.Helper()
	tok, err := e.q.GetOAuthTokenByHash(context.Background(), oauth.HashOf(raw))
	if err != nil {
		return false, false
	}
	return true, tok.RevokedAt.Valid
}

// expireToken backdates a token's expiry so expiry paths are testable without
// waiting.
func (e *testEnv) expireToken(t *testing.T, raw string) {
	t.Helper()
	if _, err := e.db.Exec(`UPDATE oauth_tokens SET expires_at = ? WHERE hash = ?`,
		time.Now().UTC().Add(-time.Minute), oauth.HashOf(raw)); err != nil {
		t.Fatal(err)
	}
}

// flashMessage reads the one-shot notice a redirecting handler set.
func flashMessage(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == flashCookie {
			msg, err := url.QueryUnescape(ck.Value)
			if err != nil {
				t.Fatalf("undecodable flash %q: %v", ck.Value, err)
			}
			return msg
		}
	}
	t.Fatal("no flash cookie set")
	return ""
}
