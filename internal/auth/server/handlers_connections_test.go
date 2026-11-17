package server

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
)

func TestConnectionsPageListsGrants(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	rr := e.get(t, "/connections", ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("empty page status=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No connected apps") {
		t.Fatal("empty state missing")
	}

	clientID, tb := e.grantTokens(t, ck)
	// Refresh twice, so this grant is backed by six token rows rather than two.
	// Grouping is the thing under test: the page must still show one row.
	second := e.refreshOK(t, clientID, tb.RefreshToken)
	e.refreshOK(t, clientID, second.RefreshToken)

	rr = e.get(t, "/connections", ck)
	body := rr.Body.String()
	for _, want := range []string{"Test Client", clientID, testResource} {
		if !strings.Contains(body, want) {
			t.Fatalf("connections page does not mention %q", want)
		}
	}
	// One revoke form per grant is the row count, and it must not scale with the
	// number of tokens rotation has produced.
	forms := strings.Count(body, `name="client_id" value="`+clientID+`"`)
	if forms != 1 {
		t.Fatalf("%d revoke forms for one grant, want 1", forms)
	}
}

// The same client connecting to two resources is two grants, revocable
// separately — otherwise revoking access to one app silently cuts off another.
func TestConnectionsSeparatesGrantsByResource(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	for _, resource := range []string{testResource, testResourceOther} {
		q := authzQuery(clientID)
		q.Set("resource", resource)
		code := codeFromRedirect(t, e.consent(t, ck, q, "approve"))
		rr := e.postForm(t, "/token", redeemForm(clientID, code))
		if rr.Code != http.StatusOK {
			t.Fatalf("token for %s: status=%d body=%s", resource, rr.Code, rr.Body.String())
		}
	}

	body := e.get(t, "/connections", ck).Body.String()
	if !strings.Contains(body, testResource) || !strings.Contains(body, testResourceOther) {
		t.Fatal("both audiences should be listed")
	}

	// Revoking one leaves the other standing.
	if rr := e.postForm(t, "/connections/revoke", url.Values{
		"client_id": {clientID},
		"resource":  {testResource},
	}, ck); rr.Code != http.StatusFound {
		t.Fatalf("revoke status=%d", rr.Code)
	}

	body = e.get(t, "/connections", ck).Body.String()
	if strings.Contains(body, testResource) {
		t.Fatal("revoked grant still listed")
	}
	if !strings.Contains(body, testResourceOther) {
		t.Fatal("revoking one grant took the other with it")
	}
}

func TestConnectionsRevokeKillsTheTokens(t *testing.T) {
	e := setup(t)
	userID, ck := e.userCookie(t, "alice@example.com")
	apiKey := e.mkAPIKey(t, userID)
	clientID, tb := e.grantTokens(t, ck)

	if rr := e.postForm(t, "/connections/revoke", url.Values{
		"client_id": {clientID},
		"resource":  {testResource},
	}, ck); rr.Code != http.StatusFound {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}

	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("access token survived a user revoking the app")
	}
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("refresh token survived revocation: status=%d", rr.Code)
	}
}

// One user must not see or be able to revoke another user's grants.
func TestConnectionsAreScopedToTheUser(t *testing.T) {
	e := setup(t)
	e.mkUser(t, "alice@example.com")
	bobID := e.mkUser(t, "bob@example.com")
	aliceCk := e.userLoginCookie(t, "alice@example.com")
	bobCk := e.userLoginCookie(t, "bob@example.com")
	apiKey := e.mkAPIKey(t, bobID)

	clientID, bobTokens := e.grantTokens(t, bobCk)

	if body := e.get(t, "/connections", aliceCk).Body.String(); strings.Contains(body, clientID) {
		t.Fatal("alice can see bob's grant")
	}
	// Alice aims a revoke at bob's grant.
	if rr := e.postForm(t, "/connections/revoke", url.Values{
		"client_id": {clientID},
		"resource":  {testResource},
	}, aliceCk); rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
	if _, resp := e.introspect(t, apiKey, bobTokens.AccessToken, testResource); !resp.Active {
		t.Fatal("alice revoked bob's grant")
	}
}

func TestConnectionsRequiresLogin(t *testing.T) {
	e := setup(t)
	rr := e.get(t, "/connections", nil)
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/login") {
		t.Fatalf("status=%d loc=%q, want redirect to login", rr.Code, rr.Header().Get("Location"))
	}
}

func TestAdminClientsPage(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	clientID := e.mkClient(t)

	rr := e.get(t, "/admin/clients", adminCk)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{clientID, "Test Client", testRedirectURI} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin clients page does not mention %q", want)
		}
	}
}

// Deleting a client revokes its grants for everyone, via the schema's cascade.
func TestAdminClientDeleteCascadesToTokens(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	_, adminCk := e.loginStatus(t, "admin@example.com", "admin-pw")
	apiKey := e.mkAPIKey(t, adminID)
	clientID, tb := e.grantTokens(t, adminCk)

	if rr := e.postForm(t, "/admin/clients/"+clientID+"/delete", url.Values{}, adminCk); rr.Code != http.StatusFound {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("token survived deletion of its client")
	}

	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM oauth_tokens WHERE client_id = ?`, clientID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d token rows left behind after the client was deleted", n)
	}
}

func TestAdminClientsRequiresAdmin(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	if rr := e.get(t, "/admin/clients", ck); rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rr.Code)
	}
}

// Disabling an account must take its OAuth grants with it, not just its sessions.
// A token lives in another app's memory where no admin can see it.
func TestDisablingUserRevokesGrants(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	_, adminCk := e.loginStatus(t, "admin@example.com", "admin-pw")
	apiKey := e.mkAPIKey(t, adminID)

	bobID, bobCk := e.userCookie(t, "bob@example.com")
	clientID, tb := e.grantTokens(t, bobCk)

	if rr := e.postForm(t, "/admin/users/"+bobID+"/disable", url.Values{}, adminCk); rr.Code != http.StatusFound {
		t.Fatalf("disable status=%d body=%s", rr.Code, rr.Body.String())
	}

	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("a disabled user's access token still verified")
	}
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("a disabled user's refresh token still worked: status=%d", rr.Code)
	}
}

// Same reasoning for a password reset: whoever prompted the reset must not keep
// access through an app they authorized during their window.
func TestPasswordResetRevokesGrants(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	_, adminCk := e.loginStatus(t, "admin@example.com", "admin-pw")
	apiKey := e.mkAPIKey(t, adminID)

	bobID, bobCk := e.userCookie(t, "bob@example.com")
	clientID, tb := e.grantTokens(t, bobCk)

	token := e.issueReset(t, adminCk, bobID)
	if rr := e.postReset(t, token, "brand-new-password", "brand-new-password"); rr.Code != http.StatusFound {
		t.Fatalf("reset status=%d body=%s", rr.Code, rr.Body.String())
	}

	if _, resp := e.introspect(t, apiKey, tb.AccessToken, testResource); resp.Active {
		t.Fatal("access token survived a password reset")
	}
	if rr := e.refresh(t, clientID, tb.RefreshToken, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("refresh token survived a password reset: status=%d", rr.Code)
	}
}

// The navigation must actually reach the new page, or it is not really in the UI.
func TestConnectionsIsLinkedFromChrome(t *testing.T) {
	e := setup(t)
	_, ck := e.userCookie(t, "alice@example.com")

	for _, path := range []string{"/", "/keys", "/connections"} {
		body := e.get(t, path, ck).Body.String()
		if !strings.Contains(body, `href="/connections"`) {
			t.Fatalf("%s does not link to /connections", path)
		}
	}
}

func TestAdminClientsIsLinkedFromAdmin(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)

	body := e.get(t, "/admin", adminCk).Body.String()
	if !strings.Contains(body, `href="/admin/clients"`) {
		t.Fatal("/admin does not link to /admin/clients")
	}
}

// firstApprover reads the attribution column directly, so a failure can tell
// "nobody was recorded" apart from "the page failed to render who was".
func (e *testEnv) firstApprover(t *testing.T, clientID string) sql.NullString {
	t.Helper()
	var got sql.NullString
	if err := e.db.QueryRow(
		`SELECT first_approved_by FROM oauth_clients WHERE id = ?`, clientID,
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

// Approving on the consent screen is the only thing that gives a self-registered
// client an owner, and the admin page is where that becomes visible.
func TestAdminClientsShowsFirstApprover(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	aliceID, aliceCk := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	if rr := e.consent(t, aliceCk, authzQuery(clientID), "approve"); rr.Code != http.StatusFound {
		t.Fatalf("consent status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := e.firstApprover(t, clientID); !got.Valid || got.String != aliceID {
		t.Fatalf("first_approved_by=%+v, want %s", got, aliceID)
	}
	if body := e.get(t, "/admin/clients", adminCk).Body.String(); !strings.Contains(body, "alice@example.com") {
		t.Fatalf("admin clients page does not name the approver:\n%s", body)
	}
}

// A client that registered and was never approved must name nobody: /register is
// unauthenticated, so attributing a row on the strength of registration alone
// would be a fabrication.
func TestAdminClientsLeavesUnapprovedClientUnattributed(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	e.mkUser(t, "alice@example.com") // exists, but approves nothing
	clientID := e.mkClient(t)

	if got := e.firstApprover(t, clientID); got.Valid {
		t.Fatalf("registration alone attributed the client to %q", got.String)
	}

	body := e.get(t, "/admin/clients", adminCk).Body.String()
	if !strings.Contains(body, clientID) {
		t.Fatal("unapproved client missing from the admin page entirely")
	}
	if strings.Contains(body, "alice@example.com") {
		t.Fatal("an unapproved client was attributed to a user")
	}
	// Under 600px data-label is the only header a cell gets, so a dropped cell
	// silently mislabels every cell after it.
	if !strings.Contains(body, `data-label="First approved by"`) {
		t.Fatal("First approved by cell not rendered")
	}
}

// First approver wins. Later approvals — by anyone, including the first user again
// — must leave the attribution alone, or the column drifts into "most recent
// approver" and stops answering whose client this is.
func TestAdminClientsKeepsTheFirstApprover(t *testing.T) {
	e := setup(t)
	adminCk := e.loginCookie(t)
	aliceID, aliceCk := e.userCookie(t, "alice@example.com")
	_, bobCk := e.userCookie(t, "bob@example.com")
	clientID := e.mkClient(t)

	for i, ck := range []*http.Cookie{aliceCk, bobCk, aliceCk} {
		if rr := e.consent(t, ck, authzQuery(clientID), "approve"); rr.Code != http.StatusFound {
			t.Fatalf("consent %d status=%d body=%s", i, rr.Code, rr.Body.String())
		}
	}

	if got := e.firstApprover(t, clientID); !got.Valid || got.String != aliceID {
		t.Fatalf("first_approved_by=%+v, want alice (%s)", got, aliceID)
	}
	body := e.get(t, "/admin/clients", adminCk).Body.String()
	if !strings.Contains(body, "alice@example.com") {
		t.Fatal("the first approver was lost")
	}
	if strings.Contains(body, "bob@example.com") {
		t.Fatal("a later approver overwrote the first")
	}
}

// Denying is not approving. The claim sits past the deny branch, and this holds it
// there.
func TestDeniedConsentDoesNotAttributeClient(t *testing.T) {
	e := setup(t)
	_, aliceCk := e.userCookie(t, "alice@example.com")
	clientID := e.mkClient(t)

	rr := e.consent(t, aliceCk, authzQuery(clientID), "deny")
	if got := redirectQuery(t, rr).Get("error"); got != oauth.ErrCodeAccessDenied {
		t.Fatalf("error=%q, want %q", got, oauth.ErrCodeAccessDenied)
	}
	if got := e.firstApprover(t, clientID); got.Valid {
		t.Fatalf("a denial attributed the client to %q", got.String)
	}
}
