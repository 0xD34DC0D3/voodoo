package server

import "testing"

func TestSafeNext(t *testing.T) {
	const domain = ".example.com"
	cases := []struct {
		name           string
		in             string
		domain         string
		allowLocalhost bool
		want           string
	}{
		{"empty", "", domain, false, ""},
		{"plain path", "/path", domain, false, "/path"},
		{"path with query", "/path?q=v", domain, false, "/path?q=v"},
		{"protocol-relative", "//evil.com", domain, false, ""},
		{"backslash open-redirect", `/\evil.com`, domain, false, ""},
		{"backslash after leading slash", `/\/evil.com`, domain, false, ""},
		{"backslash mid-path", `/foo\bar`, domain, false, ""},
		{"tab open-redirect", "/\t/evil.com", domain, false, ""},
		{"newline open-redirect", "/\n/evil.com", domain, false, ""},
		{"carriage return", "/\r/evil.com", domain, false, ""},
		{"nul byte", "/foo\x00bar", domain, false, ""},
		{"del byte", "/foo\x7fbar", domain, false, ""},
		{"tab in absolute url", "https://app.example.com/\t", ".example.com", false, ""},
		{"backslash in absolute url", `https://app.example.com\@evil.com/`, ".example.com", false, ""},
		{"no leading slash", "path", domain, false, ""},
		{"foreign absolute url", "https://evil.example.org/", domain, false, ""},
		{"sibling subdomain", "https://app.example.com/dashboard", domain, false, "https://app.example.com/dashboard"},
		{"parent domain itself", "https://example.com/x", domain, false, "https://example.com/x"},
		{"sibling but http not https", "http://app.example.com/", domain, false, ""},
		{"suffix-spoof host", "https://evilexample.com/", domain, false, ""},
		{"sibling with userinfo host trick", "https://app.example.com.evil.com/", domain, false, ""},
		{"unparseable", "https://%zz", domain, false, ""},
		{"no domain configured rejects absolute", "https://app.example.com/", "", false, ""},
		{"no domain configured allows local path", "/keys", "", false, "/keys"},
		{"localhost rejected without dev flag", "http://localhost:8081/profile", "", false, ""},
		{"localhost allowed in dev", "http://localhost:8081/profile", "", true, "http://localhost:8081/profile"},
		{"loopback ip allowed in dev", "http://127.0.0.1:8081/profile", "", true, "http://127.0.0.1:8081/profile"},
		{"dev flag does not allow foreign host", "https://evil.example.org/", domain, true, ""},
		{"dev flag still allows local path", "/keys", "", true, "/keys"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := safeNext(tc.in, tc.domain, tc.allowLocalhost)
			if got != tc.want {
				t.Errorf("safeNext(%q, %q, %v)=%q want %q", tc.in, tc.domain, tc.allowLocalhost, got, tc.want)
			}
		})
	}
}
