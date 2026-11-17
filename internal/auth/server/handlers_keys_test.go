package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/0xD34DC0D3/voodoo/internal/auth/apikey"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

// loginCookie logs the bootstrap admin in and returns the UI cookie.
func (e *testEnv) loginCookie(t *testing.T) *http.Cookie {
	t.Helper()
	ui, _ := e.loginCookies(t)
	return ui
}

// loginCookies logs the bootstrap admin in and returns both session cookies:
// the host-only UI cookie and the parent-domain one.
func (e *testEnv) loginCookies(t *testing.T) (ui, parent *http.Cookie) {
	t.Helper()
	e.mkAdmin(t)
	form := url.Values{"email": {"admin@example.com"}, "password": {"admin-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	ui, parent = sessionCookie(rr), parentCookie(rr)
	if ui == nil || parent == nil {
		t.Fatal("login did not set both session cookies")
	}
	return ui, parent
}

// insertKey writes an api_keys row directly and returns (rawKey, keyID).
func (e *testEnv) insertKey(t *testing.T, userID string, expiresAt sql.NullTime) (string, string) {
	t.Helper()
	raw, hash, prefix, err := apikey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id := ids.NewID()
	_, err = e.q.CreateApiKey(context.Background(), store.CreateApiKeyParams{
		ID:        id,
		UserID:    userID,
		Hash:      hash,
		Prefix:    prefix,
		Name:      "test",
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, id
}

func TestBearerAuthMeHappyPath(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	raw, _ := e.insertKey(t, adminID, sql.NullTime{})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/me status=%d body=%s", rr.Code, rr.Body.String())
	}
	var me struct {
		Email   string `json:"email"`
		IsAdmin bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Email != "admin@example.com" || !me.IsAdmin {
		t.Fatalf("unexpected /me: %+v", me)
	}
}

func TestMeIncludesKeyInfoForBearer(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	raw, id := e.insertKey(t, adminID, sql.NullTime{})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/me status=%d body=%s", rr.Code, rr.Body.String())
	}
	var me struct {
		Key *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"key"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Key == nil || me.Key.ID != id || me.Key.Name != "test" {
		t.Fatalf("key=%+v, want id=%s name=test", me.Key, id)
	}
}

func TestMeOmitsKeyForCookie(t *testing.T) {
	e := setup(t)
	ui, parent := e.loginCookies(t)
	for _, ck := range []*http.Cookie{ui, parent} {
		rr := e.get(t, "/me", ck)
		if rr.Code != http.StatusOK {
			t.Fatalf("/me status=%d", rr.Code)
		}
		var me map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
			t.Fatal(err)
		}
		if _, ok := me["key"]; ok {
			t.Fatalf("cookie-authenticated /me has key field: %v", me)
		}
	}
}

func TestBearerAuthBogusToken(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer ak_thisdoesnotexist")
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestBearerAuthDisabledUser(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	raw, _ := e.insertKey(t, adminID, sql.NullTime{})

	if _, err := e.db.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC(), adminID); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestBearerAuthExpiredKey(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	raw, _ := e.insertKey(t, adminID, sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := e.do(t, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

var rawKeyRE = regexp.MustCompile(`ak_[A-Za-z0-9_-]+`)

func TestPostKeysCreatesAndRevealsOnce(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)

	form := url.Values{"name": {"cli"}}
	req := httptest.NewRequest(http.MethodPost, "/keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	matches := rawKeyRE.FindAllString(body, -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 ak_ token in body, found %d: %v", len(matches), matches)
	}
	raw := matches[0]
	if !strings.HasPrefix(raw, "ak_") {
		t.Fatalf("bad raw key %q", raw)
	}

	// GET /keys should show the prefix but never the raw key.
	req = httptest.NewRequest(http.MethodGet, "/keys", nil)
	req.AddCookie(ck)
	rr = e.do(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d", rr.Code)
	}
	list := rr.Body.String()
	if strings.Contains(list, raw) {
		t.Fatal("raw key leaked into /keys listing")
	}
	prefix := raw[:12]
	if !strings.Contains(list, prefix) {
		t.Fatalf("expected prefix %q in /keys listing", prefix)
	}
}

func TestPostKeysRequiresName(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)

	form := url.Values{"name": {"   "}}
	req := httptest.NewRequest(http.MethodPost, "/keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPostKeysRejectsExpiresInDaysOverMax(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)

	form := url.Values{"name": {"cli"}, "expires_in_days": {"99999"}}
	req := httptest.NewRequest(http.MethodPost, "/keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestKeysDeleteByOwner(t *testing.T) {
	e := setup(t)
	ck := e.loginCookie(t)
	adminID, err := e.q.GetUserByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	raw, id := e.insertKey(t, adminID.ID, sql.NullTime{})

	// confirm bearer works before delete
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("pre-delete /me status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/keys/"+id+"/delete", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-delete /me status=%d", rr.Code)
	}
}

func TestKeysDeleteCrossUserNoop(t *testing.T) {
	e := setup(t)

	// user A is the bootstrap admin
	ck := e.loginCookie(t)

	// user B with their own key
	userBID := ids.NewID()
	if _, err := e.db.Exec(
		`INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)`,
		userBID, "b@example.com", "x",
	); err != nil {
		t.Fatal(err)
	}
	rawB, keyB := e.insertKey(t, userBID, sql.NullTime{})

	// user A attempts to delete user B's key.
	req := httptest.NewRequest(http.MethodPost, "/keys/"+keyB+"/delete", nil)
	req.AddCookie(ck)
	rr := e.do(t, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("delete status=%d", rr.Code)
	}

	// user B's key should still authenticate.
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+rawB)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("user B's key was wrongly removed: /me status=%d", rr.Code)
	}
}

func TestBearerTouchesLastUsedAt(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	raw, id := e.insertKey(t, adminID, sql.NullTime{})

	keys, err := e.q.ListApiKeysByUser(context.Background(), adminID)
	if err != nil {
		t.Fatal(err)
	}
	var before sql.NullTime
	for _, k := range keys {
		if k.ID == id {
			before = k.LastUsedAt
		}
	}
	if before.Valid {
		t.Fatalf("expected unset last_used_at before first call, got %v", before)
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if rr := e.do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}

	keys, err = e.q.ListApiKeysByUser(context.Background(), adminID)
	if err != nil {
		t.Fatal(err)
	}
	var after sql.NullTime
	for _, k := range keys {
		if k.ID == id {
			after = k.LastUsedAt
		}
	}
	if !after.Valid {
		t.Fatal("expected last_used_at to be set after bearer call")
	}
}

// An API key cannot mint another key; otherwise a leaked key could outlive its
// own revocation.
func TestPostKeysRejectsBearer(t *testing.T) {
	e := setup(t)
	adminID := e.mkAdmin(t)
	raw, _ := e.insertKey(t, adminID, sql.NullTime{})

	form := url.Values{"name": {"minted"}}
	req := httptest.NewRequest(http.MethodPost, "/keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := e.do(t, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("bearer minted a key: status=%d", rr.Code)
	}
	if n := e.countRows(t, "api_keys", "user_id", adminID); n != 1 {
		t.Fatalf("api_keys rows=%d, want 1", n)
	}
}
