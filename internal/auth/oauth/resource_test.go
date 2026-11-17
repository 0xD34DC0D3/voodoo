package oauth

import "testing"

func TestCanonicalResourceAccepts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain https", "https://app.example.com", "https://app.example.com"},
		{"bare slash folds away", "https://app.example.com/", "https://app.example.com"},
		{"path is kept", "https://app.example.com/mcp", "https://app.example.com/mcp"},
		{"trailing slash on a path is significant", "https://app.example.com/mcp/", "https://app.example.com/mcp/"},
		{"scheme is lowercased", "HTTPS://app.example.com/mcp", "https://app.example.com/mcp"},
		{"host is lowercased", "https://App.Example.COM/mcp", "https://app.example.com/mcp"},
		{"path case is preserved", "https://app.example.com/MCP", "https://app.example.com/MCP"},
		{"default https port is dropped", "https://app.example.com:443/mcp", "https://app.example.com/mcp"},
		{"default http port is dropped", "http://localhost:80/mcp", "http://localhost/mcp"},
		{"non-default port is kept", "http://localhost:8081/mcp", "http://localhost:8081/mcp"},
		{"query is preserved verbatim", "https://app.example.com/mcp?b=2&a=1", "https://app.example.com/mcp?b=2&a=1"},
		{"empty query degrades to none", "https://app.example.com/mcp?", "https://app.example.com/mcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalResource(tc.in)
			if err != nil {
				t.Fatalf("CanonicalResource(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("CanonicalResource(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Canonicalization only buys us anything if it is idempotent: the value stored as
// a token's audience is itself a valid resource indicator, and re-canonicalizing
// it at verification time must not change it.
func TestCanonicalResourceIdempotent(t *testing.T) {
	inputs := []string{
		"https://App.Example.com:443/",
		"https://app.example.com/mcp",
		"http://127.0.0.1:8081/mcp?x=1",
	}
	for _, in := range inputs {
		once, err := CanonicalResource(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		twice, err := CanonicalResource(once)
		if err != nil {
			t.Fatalf("%q (second pass on %q): %v", in, once, err)
		}
		if once != twice {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

// Spellings that differ only in the parts we normalize must collapse to one
// audience, or audience checks could be sidestepped by respelling the target.
func TestCanonicalResourceEquivalence(t *testing.T) {
	spellings := []string{
		"https://app.example.com",
		"https://app.example.com/",
		"https://APP.example.com:443",
		"HTTPS://app.Example.com:443/",
	}
	want, err := CanonicalResource(spellings[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range spellings[1:] {
		got, err := CanonicalResource(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got != want {
			t.Fatalf("CanonicalResource(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestCanonicalResourceRejects(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty", "", ErrResourceMissing},
		{"relative path", "/mcp", ErrResourceInvalid},
		{"scheme-relative", "//app.example.com/mcp", ErrResourceInvalid},
		{"no authority", "urn:example:resource", ErrResourceInvalid},
		{"fragment", "https://app.example.com/mcp#frag", ErrResourceInvalid},
		{"bare fragment marker", "https://app.example.com/mcp#", ErrResourceInvalid},
		{"userinfo", "https://user:pw@app.example.com/mcp", ErrResourceInvalid},
		{"no scheme", "app.example.com/mcp", ErrResourceInvalid},
		{"empty host", "https:///mcp", ErrResourceInvalid},
		{"not a url", "https://%zz", ErrResourceInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalResource(tc.in)
			if err != tc.wantErr {
				t.Fatalf("CanonicalResource(%q) err = %v (result %q), want %v", tc.in, err, got, tc.wantErr)
			}
		})
	}
}

func TestCanonicalResourceParam(t *testing.T) {
	if _, err := CanonicalResourceParam(nil); err != ErrResourceMissing {
		t.Fatalf("no values: err = %v, want %v", err, ErrResourceMissing)
	}
	got, err := CanonicalResourceParam([]string{"https://app.example.com/"})
	if err != nil || got != "https://app.example.com" {
		t.Fatalf("one value: %q, %v", got, err)
	}
	// Multiple audiences would produce a token broader than the request that
	// created it, so the request is refused rather than narrowed silently.
	_, err = CanonicalResourceParam([]string{"https://a.example.com", "https://b.example.com"})
	if err != ErrResourceMultiple {
		t.Fatalf("two values: err = %v, want %v", err, ErrResourceMultiple)
	}
}

func TestResourceErrorCode(t *testing.T) {
	if got := ResourceErrorCode(ErrResourceMissing); got != ErrCodeInvalidRequest {
		t.Fatalf("missing -> %q, want %q", got, ErrCodeInvalidRequest)
	}
	for _, err := range []error{ErrResourceInvalid, ErrResourceMultiple} {
		if got := ResourceErrorCode(err); got != ErrCodeInvalidTarget {
			t.Fatalf("%v -> %q, want %q", err, got, ErrCodeInvalidTarget)
		}
	}
}

// An IPv6 literal must survive canonicalization as a parseable URI. Dropping the
// brackets breaks idempotence, and idempotence is what lets a stored audience be
// compared against a resource server's own spelling of itself.
func TestCanonicalResourceIPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://[::1]:8081/mcp", "http://[::1]:8081/mcp"},
		{"http://[::1]:80/mcp", "http://[::1]/mcp"},
		{"https://[2001:DB8::1]/mcp", "https://[2001:db8::1]/mcp"},
		{"https://[2001:db8::1]:443/", "https://[2001:db8::1]"},
	}
	for _, tc := range cases {
		got, err := CanonicalResource(tc.in)
		if err != nil {
			t.Fatalf("CanonicalResource(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("CanonicalResource(%q) = %q, want %q", tc.in, got, tc.want)
		}
		again, err := CanonicalResource(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q (err %v)", tc.in, got, again, err)
		}
	}
}
