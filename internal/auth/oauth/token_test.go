package oauth

import (
	"strings"
	"testing"
)

func TestNewSecret(t *testing.T) {
	raw, hash := NewSecret(AccessTokenPrefix)
	if !strings.HasPrefix(raw, AccessTokenPrefix) {
		t.Fatalf("raw = %q, want %q prefix", raw, AccessTokenPrefix)
	}
	if hash != HashOf(raw) {
		t.Fatal("returned hash does not match HashOf(raw)")
	}
	// 32 random bytes as unpadded base64url.
	if body := strings.TrimPrefix(raw, AccessTokenPrefix); len(body) != 43 {
		t.Fatalf("secret body length = %d, want 43", len(body))
	}

	if other, _ := NewSecret(AccessTokenPrefix); other == raw {
		t.Fatal("NewSecret returned the same secret twice")
	}
}

func TestNewClientIDUnique(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		id := NewClientID()
		if !strings.HasPrefix(id, ClientIDPrefix) {
			t.Fatalf("client id = %q, want %q prefix", id, ClientIDPrefix)
		}
		if seen[id] {
			t.Fatalf("duplicate client id %q", id)
		}
		seen[id] = true
	}
}
