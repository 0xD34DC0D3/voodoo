package ids

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNewIDUniqueAndLowercaseBase32(t *testing.T) {
	seen := make(map[string]struct{})
	for range 100 {
		id := NewID()
		if len(id) != 26 {
			t.Errorf("len(id)=%d want 26", len(id))
		}
		for _, r := range id {
			if !(r >= 'a' && r <= 'z') && !(r >= '2' && r <= '7') {
				t.Errorf("non lowercase-base32 char %q in %q", r, id)
			}
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewTokenUniqueAndURLSafe(t *testing.T) {
	seen := make(map[string]struct{})
	for range 100 {
		tok := NewToken()
		if len(tok) != 43 {
			t.Errorf("len(tok)=%d want 43", len(tok))
		}
		for _, r := range tok {
			if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				t.Errorf("non url-safe char %q in %q", r, tok)
			}
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

// HashToken is a lookup key, so it has to be stable: the digest computed at
// login must equal the one computed on every later request, forever. A salted
// or otherwise non-deterministic hash would compile fine and log everyone out.
func TestHashTokenIsDeterministicAndOneWay(t *testing.T) {
	tok := NewToken()

	first := HashToken(tok)
	if second := HashToken(tok); first != second {
		t.Fatalf("HashToken not deterministic: %q vs %q", first, second)
	}

	// Plain SHA-256 hex, matching apikey.HashOf and oauth.HashOf so all four
	// credential types store the same shape.
	want := sha256.Sum256([]byte(tok))
	if first != hex.EncodeToString(want[:]) {
		t.Fatalf("HashToken(%q)=%q, want sha256 hex %q", tok, first, hex.EncodeToString(want[:]))
	}
	if len(first) != 64 {
		t.Fatalf("len(digest)=%d want 64", len(first))
	}

	// Distinct tokens must not collide, and the digest must not be the token —
	// the whole point is that what is stored is not what is presented.
	if HashToken(NewToken()) == first {
		t.Fatal("two random tokens hashed to the same digest")
	}
	if first == tok {
		t.Fatal("digest equals the raw token")
	}
	// A digest fed back in is just another string, not a fixed point: hashing
	// twice must not land back on the stored value, which is what makes
	// double-hashing a lookup a hard failure rather than a silent success.
	if HashToken(first) == first {
		t.Fatal("HashToken is a fixed point on its own output")
	}
}
