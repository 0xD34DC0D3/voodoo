package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
)

// Regression tests for defects found in security review. Each one names the
// property that was broken, because the fix is only worth as much as the test that
// stops it from being undone.

// A consent screen that hides where the code goes is a phishing surface: every
// other field on the page is attacker-chosen, so the redirect destination is the
// only thing a user can actually judge.
func TestConsentScreenShowsRedirectDestination(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	// A client whose name and resource both look legitimate but whose redirect
	// target does not belong to this deployment at all.
	clientID := e.mkClient(t, "https://evil.example.com/cb")
	q := authzQuery(clientID)
	q.Set("redirect_uri", "https://evil.example.com/cb")

	body := e.get(t, "/authorize?"+q.Encode(), ck).Body.String()
	if !strings.Contains(body, "evil.example.com") {
		t.Fatalf("consent page never names the host that will receive the code:\n%s", body)
	}
}

func TestConsentPageIsNotCacheable(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	rr := e.get(t, "/authorize?"+authzQuery(clientID).Encode(), ck)
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store — the page carries a live consent token", got)
	}
}

// The authorization code travels in a Location header, which is exactly the kind of
// response an intermediary is happy to cache. Every OAuth response has to carry
// no-store, and the redirect carrying a live credential most of all.
func TestEveryOAuthResponseIsUncacheable(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	approved := e.consent(t, ck, authzQuery(clientID), "approve")
	if got := approved.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("authorization redirect Cache-Control = %q, want no-store — its Location carries a code", got)
	}

	denied := e.consent(t, ck, authzQuery(clientID), "deny")
	if got := denied.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("authorization error redirect Cache-Control = %q, want no-store", got)
	}

	revoked := e.postForm(t, "/revoke", url.Values{"token": {"vat_x"}, "client_id": {clientID}})
	if got := revoked.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("/revoke Cache-Control = %q, want no-store", got)
	}
}

// Introspection is for resource servers, which hold an API key. A browser session
// must not reach it, or any logged-in user could test token strings for a living.
func TestIntrospectRejectsSessionAuth(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	_, tb := e.grantTokens(t, ck)

	rr := e.postForm(t, "/introspect", url.Values{
		"token":    {tb.AccessToken},
		"resource": {testResource},
	}, ck)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401 — a session cookie is not resource-server credentials", rr.Code)
	}
}

// The consent token must commit to the request it approves, so a token harvested
// from one consent screen cannot approve a different client or audience.
func TestConsentTokenIsBoundToTheRequest(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	victim := e.mkClient(t)
	attacker := e.mkClient(t)

	// A token legitimately issued for the victim client's consent screen.
	csrf := e.consentCSRF(t, ck, authzQuery(victim))

	// Replayed against a POST approving a different client.
	rr := e.postForm(t, "/authorize", consentForm(authzQuery(attacker), csrf, "approve"), ck)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 — a consent token must not transfer between requests", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("minted a code for a substituted client: Location=%q", loc)
	}

	// Swapping only the audience must fail too.
	swapped := authzQuery(victim)
	swapped.Set("resource", testResourceOther)
	if rr := e.postForm(t, "/authorize", consentForm(swapped, csrf, "approve"), ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("audience swap status=%d, want 400", rr.Code)
	}
}

// Refresh rotation must be atomic. Two concurrent redemptions of one refresh token
// used to both succeed, producing two live rotation chains in a single family and a
// reuse that detection could never see.
func TestConcurrentRefreshRedeemsOnce(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	const racers = 8
	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			form := url.Values{
				"grant_type":    {grantRefreshToken},
				"client_id":     {clientID},
				"refresh_token": {tb.RefreshToken},
			}
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			<-start
			e.srv.Handler().ServeHTTP(rr, req)
			results[i] = rr
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, rr := range results {
		switch rr.Code {
		case http.StatusOK:
			wins++
		case http.StatusBadRequest:
		default:
			t.Fatalf("racer %d: unexpected status %d body=%s", i, rr.Code, rr.Body.String())
		}
	}
	if wins != 1 {
		t.Fatalf("%d of %d concurrent redemptions of one refresh token succeeded, want exactly 1", wins, racers)
	}
	// Every loser saw reuse, so the winner's new tokens are revoked too.
	for _, rr := range results {
		if rr.Code == http.StatusOK {
			if _, revoked := e.tokenState(t, decodeTokens(t, rr).RefreshToken); !revoked {
				t.Fatal("the race winner's refresh token survived a lost race")
			}
		}
	}
}

// Revoking a grant has to invalidate codes as well as tokens. A code issued moments
// before revocation was still redeemable for a fresh full-lifetime grant, which made
// the revocation reversible by whoever held it.
func TestRevokingAGrantKillsOutstandingCodes(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	clientID, _ := e.grantTokens(t, ck)
	// A second authorization is approved but not yet redeemed.
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	if rr := e.postForm(t, "/connections/revoke", url.Values{
		"client_id": {clientID},
		"resource":  {testResource},
	}, ck); rr.Code != http.StatusFound {
		t.Fatalf("revoke status=%d", rr.Code)
	}

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an outstanding code survived revocation: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPasswordResetKillsOutstandingCodes(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)
	_, adminCk := e.loginStatus(t, "admin@example.com", "admin-pw")

	bobID, bobCk := e.userCookie(t, "bob@example.com")
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, bobCk, authzQuery(clientID), "approve"))

	token := e.issueReset(t, adminCk, bobID)
	if rr := e.postReset(t, token, "brand-new-password", "brand-new-password"); rr.Code != http.StatusFound {
		t.Fatalf("reset status=%d", rr.Code)
	}

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("a code issued before the reset still redeemed: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// "Revoke sessions" is the admin's first-response containment button. If it leaves
// OAuth grants alive it reports containment it did not achieve.
func TestAdminRevokeSessionsAlsoRevokesGrants(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	_, adminCk := e.loginStatus(t, "admin@example.com", "admin-pw")
	apiKey := e.mkAPIKey(t, adminID)

	bobID, bobCk := e.userCookie(t, "bob@example.com")
	clientID, tb := e.grantTokens(t, bobCk)
	code := codeFromRedirect(t, e.consent(t, bobCk, authzQuery(clientID), "approve"))

	if rr := e.postForm(t, "/admin/users/"+bobID+"/sessions/revoke", url.Values{}, adminCk); rr.Code != http.StatusFound {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}

	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("access token survived admin session revocation")
	}
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("refresh token survived admin session revocation: status=%d", rr.Code)
	}
	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an outstanding code survived admin session revocation: status=%d", rr.Code)
	}
}

// A per-IP limiter that keys on a caller-supplied header is not a limiter.
func TestRegisterRateLimitIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	e := setup(t)
	const body = `{"redirect_uris":["https://example.com/cb"]}`

	post := func(xff string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		return e.do(t, req)
	}

	// Burn the burst with a fresh spoofed address each time. httptest's RemoteAddr
	// is 192.0.2.1 — a public documentation address, so not a trusted proxy — and
	// the header must therefore be ignored.
	for i := range 5 {
		if rr := post("10.0.0." + string(rune('1'+i))); rr.Code != http.StatusCreated {
			t.Fatalf("registration %d status=%d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	if rr := post("10.9.9.9"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429 — a spoofed X-Forwarded-For bought a fresh bucket", rr.Code)
	}
}

// The "Approved" column exists to tell a user when they granted access. Rotation
// must not make it read as today.
func TestConnectionsShowsOriginalApprovalTime(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	// Backdate the approval, then rotate. The rotated-in rows are new; the approval is
	// not, and rotation has to carry granted_at forward rather than restamping it.
	if _, err := e.db.Exec(`UPDATE oauth_tokens SET granted_at = '2020-01-02 03:04:00' WHERE client_id = ?`, clientID); err != nil {
		t.Fatal(err)
	}
	e.refreshOK(t, clientID, tb.RefreshToken)

	body := e.get(t, "/connections", ck).Body.String()
	if !strings.Contains(body, "2020-01-02") {
		t.Fatalf("connections page lost the original approval date after rotation:\n%s", body)
	}
}

// A fully revoked grant must disappear from the page even though its rows are still
// readable (they are what carry the original approval time).
func TestConnectionsHidesFullyRevokedGrants(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	if rr := e.postForm(t, "/revoke", url.Values{
		"token":     {tb.RefreshToken},
		"client_id": {clientID},
	}); rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", rr.Code)
	}

	if body := e.get(t, "/connections", ck).Body.String(); strings.Contains(body, clientID) {
		t.Fatal("a fully revoked grant is still listed as connected")
	}
}

func TestAdminClientDeleteReportsMisses(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)

	rr := e.postForm(t, "/admin/clients/vc_doesnotexist/delete", url.Values{}, adminCk)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
	// The message rides a flash cookie to the page after the redirect, so read it
	// there rather than fetching /admin/clients without carrying the cookie over.
	got := flashMessage(t, rr)
	if !strings.Contains(got, "No such client") {
		t.Fatalf("flash = %q, want it to say nothing was deleted", got)
	}

	// A real client still reports the revocation it performed.
	clientID := e.mkClient(t)
	rr = e.postForm(t, "/admin/clients/"+clientID+"/delete", url.Values{}, adminCk)
	if got := flashMessage(t, rr); !strings.Contains(got, "revoked") {
		t.Fatalf("flash = %q, want it to confirm the deletion", got)
	}
}

// expires_in must never be zero or negative: clients schedule renewal from it.
// An access token must never outlive the authorization it descends from, and
// expires_in must never be zero: clients schedule renewal from it.
func TestAccessTokenIsClampedToTheFamilyDeadline(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	// A whole hour of access TTL against a family with seconds left. Without the
	// clamp the response would advertise the full 3600.
	e.srv.cfg.OAuthAccessTTL = time.Hour
	if _, err := e.db.Exec(
		`UPDATE oauth_tokens SET expires_at = datetime('now', '+20 seconds') WHERE kind = 'refresh' AND revoked_at IS NULL`,
	); err != nil {
		t.Fatal(err)
	}

	got := e.refreshOK(t, clientID, tb.RefreshToken)
	if got.ExpiresIn < 1 || got.ExpiresIn > 20 {
		t.Fatalf("expires_in = %d, want it clamped into (0, 20] by the family deadline", got.ExpiresIn)
	}
}

// A family with nothing left is not refreshable into a token that dies in flight.
func TestExpiredFamilyIsNotRefreshable(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	if _, err := e.db.Exec(
		`UPDATE oauth_tokens SET expires_at = datetime('now', '-1 second') WHERE kind = 'refresh' AND revoked_at IS NULL`,
	); err != nil {
		t.Fatal(err)
	}

	rr := e.refresh(t, clientID, tb.RefreshToken, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidGrant {
		t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidGrant)
	}
}

// A resource that cannot be parsed is a malformed request, not a target this server
// declines to serve — the client needs to know which.
func TestTokenMalformedResourceIsInvalidRequest(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	rr := e.postForm(t, "/token", url.Values{
		"grant_type": {grantAuthorizationCode}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {testRedirectURI}, "code_verifier": {testVerifier},
		"resource": {""},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidRequest {
		t.Fatalf("error = %q, want %q for an empty resource", got, oauth.ErrCodeInvalidRequest)
	}
}

func TestRegisterRejectsOverlongClientURI(t *testing.T) {
	e := setup(t)
	long := "https://example.com/" + strings.Repeat("a", oauth.MaxURILen)
	rr := e.postJSON(t, "/register", `{"redirect_uris":["https://e.com/cb"],"client_uri":"`+long+`"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

// A single-host deployment sets no cookie domain. Without a fallback the parent-domain
// rule trusts nothing and OAuth silently stops working entirely.
func TestResourcePolicyOnSingleHostDeployment(t *testing.T) {
	e := setup(t)
	e.srv.cfg.CookieSecure = true
	e.srv.cfg.CookieDomain = ""
	e.srv.cfg.BaseURL = "https://voodoo.example.com"

	cases := []struct {
		resource string
		want     bool
	}{
		{"https://voodoo.example.com/mcp", true},
		{"https://voodoo.example.com", true},
		{"https://VOODOO.example.com:443/mcp", true},
		{"https://other.example.com/mcp", false},
		{"http://voodoo.example.com/mcp", false},
		{"https://voodoo.example.com.evil.com/mcp", false},
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

// A client row stored under looser rules must not be redirected to, and its
// homepage must not be shown.
func TestAuthorizeRevalidatesStoredClient(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	bad := "http://user@127.0.0.1:49152/callback"
	if _, err := e.q.CreateOAuthClient(context.Background(), store.CreateOAuthClientParams{
		ID:           "vc_legacy",
		Name:         "Legacy",
		RedirectUris: oauth.EncodeRedirectURIs([]string{bad}),
	}); err != nil {
		t.Fatal(err)
	}
	q := authzQuery("vc_legacy")
	q.Set("redirect_uri", bad)
	assertAuthzErrorPage(t, e.get(t, "/authorize?"+q.Encode(), ck))

	if _, err := e.q.CreateOAuthClient(context.Background(), store.CreateOAuthClientParams{
		ID:           "vc_badhome",
		Name:         "Bad Home",
		RedirectUris: oauth.EncodeRedirectURIs([]string{testRedirectURI}),
		ClientUri:    nullString("https://trusted.example.com@evil.example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	rr := e.get(t, "/authorize?"+authzQuery("vc_badhome").Encode(), ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "evil.example.com") {
		t.Fatal("an invalid stored client_uri was shown")
	}
}

func TestRegisterStripsBidiFromClientName(t *testing.T) {
	e := setup(t)
	rr := e.postJSON(t, "/register", `{"client_name":"Evil\u202eppA","redirect_uris":["`+testRedirectURI+`"]}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "\\u202e") || !strings.Contains(rr.Body.String(), `"client_name":"EvilppA"`) {
		t.Fatalf("name not sanitized: %s", rr.Body.String())
	}
}

func TestRegisterRejectsUserinfoAndNonASCII(t *testing.T) {
	e := setup(t)
	for _, body := range []string{
		`{"redirect_uris":["https://good.example.com@evil.example.com/cb"]}`,
		`{"redirect_uris":["https://\u0430pp.example.com/cb"]}`,
		`{"redirect_uris":["` + testRedirectURI + `"],"client_uri":"https://u@app.example.com"}`,
		`{"redirect_uris":["` + testRedirectURI + `"],"client_uri":"https://\u0430pp.example.com"}`,
	} {
		if rr := e.postJSON(t, "/register", body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", body, rr.Code)
		}
	}
}

func TestConsentLabelsHomepageSelfReported(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	rr := e.postJSON(t, "/register", `{"client_uri":"https://app.example.com","redirect_uris":["`+testRedirectURI+`"]}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register status=%d", rr.Code)
	}
	var resp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	body := e.get(t, "/authorize?"+authzQuery(resp.ClientID).Encode(), ck).Body.String()
	if !strings.Contains(body, "Homepage (self-reported, unverified)") {
		t.Fatalf("homepage not labelled self-reported: %s", body)
	}
}

// Parameters in the query string of an OAuth POST are ignored.
func TestOAuthPostsIgnoreQueryParameters(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, tb := e.grantTokens(t, ck)

	post := func(path string, q url.Values, body url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path+"?"+q.Encode(), strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.AddCookie(ck)
		return e.do(t, req)
	}
	empty := url.Values{}

	refresh := url.Values{"grant_type": {grantRefreshToken}, "client_id": {clientID}, "refresh_token": {tb.RefreshToken}}
	if rr := post("/token", refresh, empty); rr.Code != http.StatusBadRequest {
		t.Fatalf("/token status=%d, want 400", rr.Code)
	}
	introspect := url.Values{"token": {tb.AccessToken}, "resource": {testResource}}
	if rr := post("/introspect", introspect, empty); rr.Code != http.StatusBadRequest {
		t.Fatalf("/introspect status=%d, want 400", rr.Code)
	}
	if rr := post("/revoke", url.Values{"token": {tb.RefreshToken}, "client_id": {clientID}}, empty); rr.Code != http.StatusBadRequest {
		t.Fatalf("/revoke status=%d, want 400", rr.Code)
	}
	q := authzQuery(clientID)
	assertAuthzErrorPage(t, post("/authorize", consentForm(q, e.consentCSRF(t, ck, q), "approve"), empty))

	// The refresh token was never spent.
	e.refreshOK(t, clientID, tb.RefreshToken)
}
