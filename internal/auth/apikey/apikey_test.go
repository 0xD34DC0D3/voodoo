package apikey

import (
	"strings"
	"testing"
)

func TestGenerateRoundTrip(t *testing.T) {
	raw, hash, prefix, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(raw, "ak_") {
		t.Errorf("raw missing ak_ prefix: %q", raw)
	}
	if len(prefix) != 12 {
		t.Errorf("len(prefix)=%d want 12", len(prefix))
	}
	if prefix != raw[:12] {
		t.Errorf("prefix=%q want %q", prefix, raw[:12])
	}
	if HashOf(raw) != hash {
		t.Errorf("HashOf(raw) != hash")
	}
	if len(hash) != 64 {
		t.Errorf("len(hash)=%d want 64", len(hash))
	}
}

func TestGenerateUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for range 50 {
		raw, _, _, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[raw]; dup {
			t.Fatalf("duplicate raw key: %q", raw)
		}
		seen[raw] = struct{}{}
	}
}

func TestParseBearer(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"good", "Bearer ak_abc123", "ak_abc123", true},
		{"lowercase scheme", "bearer ak_abc123", "ak_abc123", true},
		{"mixed case scheme", "BeArEr ak_abc123", "ak_abc123", true},
		{"empty", "", "", false},
		{"scheme only", "Bearer ", "", false},
		{"scheme only no space", "Bearer", "", false},
		{"wrong scheme", "Token ak_abc123", "", false},
		{"basic auth", "Basic dXNlcjpwYXNz", "", false},
		{"no ak_ prefix", "Bearer something-else", "", false},
		{"trailing space", "Bearer ak_abc123 ", "", false},
		{"leading extra space", "Bearer  ak_abc123", "", false},
		{"double bearer", "Bearer Bearer ak_abc123", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseBearer(tc.header)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v (got=%q)", ok, tc.ok, got)
			}
			if got != tc.want {
				t.Errorf("got=%q want %q", got, tc.want)
			}
		})
	}
}
