package config

import (
	"os"
	"testing"
)

// The bind host is the only thing keeping this process off the network — the
// host firewall does not cover it, because Docker's iptables rules bypass the
// UFW chains — so the default has to be loopback and the opt-out has to be
// deliberate.
func TestLoadBindHost(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		env  string
		want string
	}{
		{"unset defaults to loopback", false, "", "127.0.0.1"},
		{"explicit override is honoured", true, "0.0.0.0", "0.0.0.0"},
		{"IPv6 loopback passes through unchanged", true, "::1", "::1"},
		// envOr would fold this into the default; Load special-cases it so the
		// "all interfaces" escape hatch stays reachable.
		{"empty means all interfaces", true, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VOODOO_DB_PATH", "/tmp/voodoo-test.db")
			// t.Setenv first either way so its cleanup restores whatever the
			// developer's shell had; the unset case then clears it, so an
			// exported VOODOO_BIND can't quietly turn the default green.
			t.Setenv("VOODOO_BIND", tc.env)
			if !tc.set {
				os.Unsetenv("VOODOO_BIND")
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.BindHost != tc.want {
				t.Fatalf("BindHost = %q, want %q", cfg.BindHost, tc.want)
			}
		})
	}
}

func TestCheckServe(t *testing.T) {
	cases := []struct {
		name   string
		secure bool
		base   string
		domain string
		site   string
		ok     bool
	}{
		{"insecure dev needs no base url", false, "", "", "https://example.com", true},
		{"insecure rejects a cookie domain", false, "", ".example.com", "https://example.com", false},
		{"secure requires base url", true, "", "", "https://example.com", false},
		{"secure rejects http", true, "http://auth.example.com", "", "https://example.com", false},
		{"secure rejects missing host", true, "https://", "", "https://example.com", false},
		{"secure rejects bare host", true, "auth.example.com", "", "https://example.com", false},
		{"secure accepts https", true, "https://auth.example.com", "", "https://example.com", true},
		{"secure accepts https with a cookie domain", true, "https://auth.example.com", ".example.com", "https://example.com", true},
		{"secure rejects an http site url", true, "https://auth.example.com", "", "http://example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Config{CookieSecure: tc.secure, BaseURL: tc.base, CookieDomain: tc.domain, SiteURL: tc.site}).CheckServe()
			if (err == nil) != tc.ok {
				t.Fatalf("CheckServe() err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
