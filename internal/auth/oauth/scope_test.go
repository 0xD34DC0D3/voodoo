package oauth

import "testing"

func TestGrant(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		want      string
		wantOK    bool
	}{
		{"omitted defaults to everything supported", "", ScopeIdentity, true},
		{"whitespace only is the same as omitted", "   ", ScopeIdentity, true},
		{"exact request", ScopeIdentity, ScopeIdentity, true},
		{"extra scopes are dropped", "openid " + ScopeIdentity, ScopeIdentity, true},
		{"duplicates collapse", ScopeIdentity + " " + ScopeIdentity, ScopeIdentity, true},
		{"tabs and runs of spaces split the same", "\t" + ScopeIdentity + "  openid", ScopeIdentity, true},
		// Case sensitivity matters: RFC 6749 §3.3 scope tokens are case-sensitive,
		// so a near-miss is a miss, not a grant.
		{"wrong case is not a match", "VOODOO:IDENTITY", "", false},
		{"nothing supported", "openid profile", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Grant(tc.requested)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("Grant(%q) = (%q, %v), want (%q, %v)", tc.requested, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// The discovery document hands this slice to a JSON encoder; a caller mutating it
// would silently rewrite the server's advertised policy for every later request.
func TestSupportedScopesIsACopy(t *testing.T) {
	first := SupportedScopes()
	first[0] = "tampered"
	if SupportedScopes()[0] != ScopeIdentity {
		t.Fatal("SupportedScopes returned aliased backing storage")
	}
}

func TestScopeDescriptionsAreTotal(t *testing.T) {
	for _, s := range SupportedScopes() {
		got := ScopeDescriptions(s)
		if len(got) != 1 || got[0] == "" || got[0] == s {
			t.Fatalf("ScopeDescriptions(%q) = %q — supported scopes need a human sentence for the consent screen", s, got)
		}
	}
	// An unknown scope degrades to its own name rather than a blank row.
	if got := ScopeDescriptions("unknown:scope"); len(got) != 1 || got[0] != "unknown:scope" {
		t.Fatalf("ScopeDescriptions fallback = %q", got)
	}
	// One entry per scope, in order.
	if got := ScopeDescriptions("a b"); len(got) != 2 {
		t.Fatalf("ScopeDescriptions(%q) = %q, want one entry per scope", "a b", got)
	}
	if got := ScopeDescriptions(""); len(got) != 0 {
		t.Fatalf("ScopeDescriptions(\"\") = %q, want empty", got)
	}
}

func TestNarrow(t *testing.T) {
	cases := []struct {
		name                     string
		granted, requested, want string
		ok                       bool
	}{
		{"empty request keeps the grant", ScopeIdentity, "", ScopeIdentity, true},
		{"exact restatement", ScopeIdentity, ScopeIdentity, ScopeIdentity, true},
		{"widening is refused", ScopeIdentity, "openid " + ScopeIdentity, "", false},
		{"unrelated scope is refused", ScopeIdentity, "openid", "", false},
		{"narrowing to nothing of the grant", "a b", "a", "a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Narrow(tc.granted, tc.requested)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("Narrow(%q, %q) = (%q, %v), want (%q, %v)",
					tc.granted, tc.requested, got, ok, tc.want, tc.ok)
			}
		})
	}
}
