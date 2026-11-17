package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
)

func TestRefreshRotatesTokens(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, first := e.grantTokens(t, ck)

	second := e.refreshOK(t, clientID, first.RefreshToken)

	// OAuth 2.1 requires rotation for public clients: a refresh token is spent by
	// using it, so the response must carry a new one.
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	if second.AccessToken == first.AccessToken {
		t.Fatal("access token was not replaced")
	}
	if second.Scope != first.Scope {
		t.Fatalf("scope drifted across refresh: %q -> %q", first.Scope, second.Scope)
	}

	// The spent token is retained but revoked — that record is what makes reuse
	// detectable rather than merely unsuccessful.
	exists, revoked := e.tokenState(t, first.RefreshToken)
	if !exists || !revoked {
		t.Fatalf("old refresh token: exists=%v revoked=%v, want true/true", exists, revoked)
	}
	if _, revoked := e.tokenState(t, second.RefreshToken); revoked {
		t.Fatal("the new refresh token was born revoked")
	}
}

// Reuse of a spent refresh token means two parties hold it and we cannot tell
// which is legitimate. The whole rotation family dies, including the token the
// honest client is currently using.
func TestRefreshReuseRevokesTheFamily(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, first := e.grantTokens(t, ck)

	second := e.refreshOK(t, clientID, first.RefreshToken)

	// An attacker replays the token the client already spent.
	rr := e.refresh(t, clientID, first.RefreshToken, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("reuse status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
	if got := oauthErrorOf(t, rr).Code; got != oauth.ErrCodeInvalidGrant {
		t.Fatalf("error = %q, want %q", got, oauth.ErrCodeInvalidGrant)
	}

	// The honest client's current refresh token is now dead too. That is the
	// intended, drastic outcome: the alternative is leaving a thief with working
	// access.
	if rr := e.refresh(t, clientID, second.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("the successor refresh token still worked: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// And the access token from that family stops verifying.
	if _, resp := e.introspect(t, apiKey, second.AccessToken, testResource); resp.Active {
		t.Fatal("an access token from a revoked family still verified")
	}
}

func TestRefreshRejections(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)
	otherClient := e.mkClient(t)

	cases := []struct {
		name     string
		clientID string
		token    string
		extra    url.Values
		wantCode string
	}{
		{"unknown token", clientID, "vrt_nope", nil, oauth.ErrCodeInvalidGrant},
		{"missing token", clientID, "", nil, oauth.ErrCodeInvalidRequest},
		// A refresh token belongs to one client; another client presenting it is
		// either confused or stealing.
		{"wrong client", otherClient, tb.RefreshToken, nil, oauth.ErrCodeInvalidGrant},
		// An access token is not a refresh token, even though both are ours.
		{"access token as refresh", clientID, tb.AccessToken, nil, oauth.ErrCodeInvalidGrant},
		{"audience change", clientID, tb.RefreshToken, url.Values{"resource": {testResourceOther}}, oauth.ErrCodeInvalidTarget},
		{"scope widening", clientID, tb.RefreshToken, url.Values{"scope": {"openid " + oauth.ScopeIdentity}}, oauth.ErrCodeInvalidScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := e.refresh(t, tc.clientID, tc.token, tc.extra)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
			}
			if got := oauthErrorOf(t, rr).Code; got != tc.wantCode {
				t.Fatalf("error = %q, want %q", got, tc.wantCode)
			}
		})
	}

	// None of the above spent the token, so the legitimate refresh still works.
	e.refreshOK(t, clientID, tb.RefreshToken)
}

func TestRefreshRejectsExpiredToken(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	e.expireToken(t, tb.RefreshToken)
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

// Rotation must not extend the absolute lifetime of an authorization. If it did,
// a client refreshing on a timer would hold access forever from a single approval.
func TestRotationDoesNotExtendTheGrant(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, first := e.grantTokens(t, ck)

	expiryOf := func(raw string) string {
		t.Helper()
		var exp string
		if err := e.db.QueryRow(`SELECT expires_at FROM oauth_tokens WHERE hash = ?`,
			oauth.HashOf(raw)).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		return exp
	}

	before := expiryOf(first.RefreshToken)
	second := e.refreshOK(t, clientID, first.RefreshToken)
	if after := expiryOf(second.RefreshToken); after != before {
		t.Fatalf("refresh expiry moved from %s to %s — rotation must carry the deadline over", before, after)
	}
}

// A disabled account cannot be refreshed back into working access.
func TestRefreshRejectsDisabledUser(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	if _, err := e.db.Exec(`UPDATE users SET disabled_at = CURRENT_TIMESTAMP WHERE id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

func TestRefreshMayNarrowScope(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID, tb := e.grantTokens(t, ck)

	// Requesting exactly what was granted is the degenerate narrowing and must work.
	rr := e.refresh(t, clientID, tb.RefreshToken, url.Values{"scope": {oauth.ScopeIdentity}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got tokenBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Scope != oauth.ScopeIdentity {
		t.Fatalf("scope = %q, want %q", got.Scope, oauth.ScopeIdentity)
	}
}

// --- Revocation (RFC 7009) ---

func TestRevokeRefreshTokenKillsTheFamily(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, tb := e.grantTokens(t, ck)

	rr := e.postForm(t, "/revoke", url.Values{
		"token":     {tb.RefreshToken},
		"client_id": {clientID},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}

	// RFC 7009 §2.1: the access tokens issued alongside go too.
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("access token survived revocation of its refresh token")
	}
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh token still worked: status=%d", rr.Code)
	}
}

func TestRevokeAccessTokenLeavesRefreshAlone(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, tb := e.grantTokens(t, ck)

	if rr := e.postForm(t, "/revoke", url.Values{
		"token":     {tb.AccessToken},
		"client_id": {clientID},
	}); rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", rr.Code)
	}

	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("revoked access token still verified")
	}
	// Revoking one access token is not revoking the authorization.
	e.refreshOK(t, clientID, tb.RefreshToken)
}

// RFC 7009 §2.2: revocation answers 200 whatever happens, so it cannot be used to
// probe whether a token string is real or whose it is.
func TestRevokeIsIndistinguishable(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, tb := e.grantTokens(t, ck)
	otherClient := e.mkClient(t)

	for _, tc := range []struct{ name, token, client string }{
		{"unknown token", "vat_nonexistent", clientID},
		{"another client's token", tb.AccessToken, otherClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := e.postForm(t, "/revoke", url.Values{
				"token":     {tc.token},
				"client_id": {tc.client},
			})
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200", rr.Code)
			}
		})
	}

	// And crucially, the mismatched-client attempt did not actually revoke anything.
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); !resp.Active {
		t.Fatal("another client's revoke request destroyed a token it does not own")
	}
}

func TestRevokeRequiresTokenAndClient(t *testing.T) {
	e := setup(t)
	for _, form := range []url.Values{
		{},
		{"token": {"vat_x"}},
		{"client_id": {"vc_x"}},
	} {
		rr := e.postForm(t, "/revoke", form)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("form %v: status=%d, want 400", form, rr.Code)
		}
	}
}

// A replayed authorization code means it was intercepted. Everything the first
// redemption minted dies with it (RFC 6749 §4.1.2).
func TestCodeReplayRevokesTheFamily(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID := e.mkClient(t)
	code := codeFromRedirect(t, e.consent(t, ck, authzQuery(clientID), "approve"))

	first := e.redeem(t, clientID, code)
	second := e.refreshOK(t, clientID, first.RefreshToken)

	rr := e.postForm(t, "/token", redeemForm(clientID, code))
	if got := oauthErrorOf(t, rr).Code; rr.Code != http.StatusBadRequest || got != oauth.ErrCodeInvalidGrant {
		t.Fatalf("replay status=%d error=%q, want 400 invalid_grant", rr.Code, got)
	}
	if _, revoked := e.tokenState(t, second.RefreshToken); !revoked {
		t.Fatal("refresh token from the replayed code's family is still live")
	}
	if _, resp := e.introspect(t, apiKey, second.AccessToken, testResource); resp.Active {
		t.Fatal("access token from the replayed code's family still verifies")
	}
}

// A database failure is the server's problem, not a bad grant: the client must
// not be told to throw its credential away.
func TestTokenDatabaseErrorIsServerError(t *testing.T) {
	cases := map[string]func(e *testEnv, clientID string, tb tokenBundle) url.Values{
		"refresh": func(e *testEnv, clientID string, tb tokenBundle) url.Values {
			e.mustExec(t, `DROP TABLE oauth_tokens`)
			return url.Values{"grant_type": {grantRefreshToken}, "client_id": {clientID}, "refresh_token": {tb.RefreshToken}}
		},
		"code": func(e *testEnv, clientID string, _ tokenBundle) url.Values {
			e.mustExec(t, `DROP TABLE oauth_codes`)
			return redeemForm(clientID, "vac_whatever")
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			_, ck := e.userCookie(t, "alice@example.com")
			clientID, tb := e.grantTokens(t, ck)
			rr := e.postForm(t, "/token", mk(e, clientID, tb))
			if got := oauthErrorOf(t, rr).Code; rr.Code != http.StatusInternalServerError || got != oauth.ErrCodeServerError {
				t.Fatalf("status=%d error=%q, want 500 server_error", rr.Code, got)
			}
		})
	}
}

func (e *testEnv) mustExec(t *testing.T, q string) {
	t.Helper()
	if _, err := e.db.Exec(q); err != nil {
		t.Fatal(err)
	}
}
