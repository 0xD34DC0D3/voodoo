package oauth

import (
	"strings"
	"testing"
)

func TestValidateRedirectURIAccepts(t *testing.T) {
	ok := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://app.example.com/cb?state=keep",
		"http://127.0.0.1:49152/callback", // RFC 8252 loopback, unpredictable port
		"http://localhost:8081/cb",
		"http://[::1]:1234/cb",
		"com.example.app:/oauth/callback", // RFC 8252 private-use scheme
	}
	for _, u := range ok {
		if err := ValidateRedirectURI(u); err != nil {
			t.Fatalf("ValidateRedirectURI(%q) = %v, want nil", u, err)
		}
	}
}

func TestValidateRedirectURIRejects(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty", "", ErrRedirectInvalid},
		{"relative", "/callback", ErrRedirectInvalid},
		{"fragment", "https://app.example.com/cb#x", ErrRedirectInvalid},
		{"bare fragment marker", "https://app.example.com/cb#", ErrRedirectInvalid},
		{"https without host", "https:///cb", ErrRedirectInvalid},
		{"overlong", "https://app.example.com/" + strings.Repeat("a", MaxURILen), ErrRedirectInvalid},
		// The rule that actually matters: a code delivered over plaintext http to
		// a routable host is a code delivered to the network.
		{"http on routable host", "http://app.example.com/cb", ErrRedirectInsecure},
		{"http on lookalike host", "http://localhost.evil.com/cb", ErrRedirectInsecure},
		{"bare private-use scheme", "app:/cb", ErrRedirectInsecure},
		{"userinfo", "https://app.example.com@evil.example.com/cb", ErrRedirectInvalid},
		{"userinfo on loopback", "http://user:pw@127.0.0.1:1234/cb", ErrRedirectInvalid},
		{"non-ASCII host", "https://аpp.example.com/cb", ErrRedirectInvalid},
		{"non-ASCII path", "https://app.example.com/cb‮", ErrRedirectInvalid},
		{"space", "https://app.example.com/c b", ErrRedirectInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRedirectURI(tc.in); err != tc.wantErr {
				t.Fatalf("ValidateRedirectURI(%q) = %v, want %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestValidateRedirectURIs(t *testing.T) {
	if err := ValidateRedirectURIs(nil); err != ErrNoRedirectURIs {
		t.Fatalf("nil: %v, want %v", err, ErrNoRedirectURIs)
	}
	many := make([]string, MaxRedirectURIs+1)
	for i := range many {
		many[i] = "https://app.example.com/cb"
	}
	if err := ValidateRedirectURIs(many); err != ErrTooManyRedirects {
		t.Fatalf("too many: %v, want %v", err, ErrTooManyRedirects)
	}
	// One bad entry poisons the whole registration — a client must not end up
	// with a partially-trusted redirect set.
	mixed := []string{"https://app.example.com/cb", "http://evil.example.com/cb"}
	if err := ValidateRedirectURIs(mixed); err != ErrRedirectInsecure {
		t.Fatalf("mixed: %v, want %v", err, ErrRedirectInsecure)
	}
	if err := ValidateRedirectURIs([]string{"https://app.example.com/cb"}); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

func TestRedirectURIRoundTrip(t *testing.T) {
	uris := []string{"https://a.example.com/cb", "http://127.0.0.1:1/cb"}
	got := DecodeRedirectURIs(EncodeRedirectURIs(uris))
	if len(got) != len(uris) {
		t.Fatalf("round trip length = %d, want %d", len(got), len(uris))
	}
	for i := range uris {
		if got[i] != uris[i] {
			t.Fatalf("round trip[%d] = %q, want %q", i, got[i], uris[i])
		}
	}
	if DecodeRedirectURIs("") != nil {
		t.Fatal("decoding empty storage should yield no URIs")
	}
}

func TestRedirectURIAllowedIsExact(t *testing.T) {
	registered := []string{"https://app.example.com/cb"}

	if !RedirectURIAllowed(registered, "https://app.example.com/cb") {
		t.Fatal("exact match rejected")
	}
	// Every one of these is "close enough" under some looser matching rule, and
	// every one of them delivers the code somewhere the client did not register.
	near := []string{
		"https://app.example.com/cb2",
		"https://app.example.com/cb/",
		"https://app.example.com/cb?next=https://evil.example.com",
		"https://app.example.com:443/cb",
		"https://APP.example.com/cb",
		"https://evil.example.com/cb",
		"http://app.example.com/cb",
		"",
	}
	for _, u := range near {
		if RedirectURIAllowed(registered, u) {
			t.Fatalf("RedirectURIAllowed(%q) = true, want false", u)
		}
	}
	if RedirectURIAllowed(nil, "https://app.example.com/cb") {
		t.Fatal("a client with no registered URIs must match nothing")
	}
}

// redirect_uris are stored newline-separated, so a URI containing a newline could
// smuggle a second, unvetted redirect target into a client's registered set. Go's
// url.Parse rejects control characters, which is what closes this — pin it, because
// the storage encoding depends on it.
func TestValidateRedirectURIRejectsControlCharacters(t *testing.T) {
	for _, raw := range []string{
		"https://app.example.com/cb\nhttps://evil.example.com/cb",
		"https://app.example.com/cb\rhttps://evil.example.com/cb",
		"https://app.example.com/cb\n",
		"https://app.example.com/\tcb",
		"https://app.example.com/cb\x00",
	} {
		if err := ValidateRedirectURI(raw); err == nil {
			t.Fatalf("ValidateRedirectURI(%q) = nil, want an error", raw)
		}
	}
}

// The round trip must survive whatever registration lets through: if any accepted
// URI could contain the separator, decoding would produce entries that were never
// validated.
func TestEncodedRedirectURIsCannotGainEntries(t *testing.T) {
	uris := []string{"https://a.example.com/cb", "com.example.app:/cb"}
	if err := ValidateRedirectURIs(uris); err != nil {
		t.Fatal(err)
	}
	if got := DecodeRedirectURIs(EncodeRedirectURIs(uris)); len(got) != len(uris) {
		t.Fatalf("decoded %d entries from %d validated URIs", len(got), len(uris))
	}
}

func TestValidateClientURI(t *testing.T) {
	for _, ok := range []string{"", "https://app.example.com", "http://app.example.com/about?x=1"} {
		if err := ValidateClientURI(ok); err != nil {
			t.Errorf("ValidateClientURI(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"javascript:alert(1)",
		"https://trusted.example.com@evil.example.com",
		"https://user@app.example.com",
		"https://аpp.example.com",
		"https://app.example.com/\u200b",
		"https://app.example.com/a b",
	} {
		if err := ValidateClientURI(bad); err != ErrClientURIScheme {
			t.Errorf("ValidateClientURI(%q) = %v, want %v", bad, err, ErrClientURIScheme)
		}
	}
}

func TestValidateClientNameStripsControlAndFormatCharacters(t *testing.T) {
	cases := map[string]string{
		"Good App":               "Good App",
		"Evil\u202eppA dooG":     "EvilppA dooG", // RLO override
		"Zero\u200bWidth":        "ZeroWidth",
		"Tab\tNew\nLine\x00":     "TabNewLine",
		"  \u200e  ":             "Unnamed client",
		"Caf\u00e9 \u65e5\u672c": "Caf\u00e9 \u65e5\u672c", // ordinary non-ASCII stays
	}
	for in, want := range cases {
		got, err := ValidateClientName(in)
		if err != nil || got != want {
			t.Errorf("ValidateClientName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
