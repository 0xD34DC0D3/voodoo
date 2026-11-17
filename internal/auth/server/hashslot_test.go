package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginGets503WhenHashSlotIsBusy(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)
	e.srv.hashWait = 50 * time.Millisecond
	e.srv.hashSlot <- struct{}{} // someone else is hashing
	defer func() { <-e.srv.hashSlot }()

	form := url.Values{"email": {"admin@example.com"}, "password": {"whatever"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := e.do(t, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func TestHashSlotIsReleased(t *testing.T) {
	e := setup(t)
	e.mkAdmin(t)
	for i := 0; i < 3; i++ {
		form := url.Values{"email": {"admin@example.com"}, "password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if rr := e.do(t, req); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i, rr.Code)
		}
	}
}
