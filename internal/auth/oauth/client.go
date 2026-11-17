package oauth

import (
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// Client registration limits. /register is unauthenticated by design — that is
// what dynamic client registration means — so every field it accepts is hostile
// input and every one of them is bounded.
const (
	MaxClientNameLen = 100
	MaxRedirectURIs  = 5
	MaxURILen        = 2048
)

var (
	ErrNoRedirectURIs   = errors.New("redirect_uris must contain at least one URI")
	ErrTooManyRedirects = errors.New("redirect_uris has too many entries")
	ErrRedirectInsecure = errors.New("redirect_uris must use https, a loopback http address, or a private-use scheme")
	ErrRedirectInvalid  = errors.New("each redirect_uri must be an absolute ASCII URI with no userinfo or fragment")
	ErrClientNameLen    = errors.New("client_name is too long")
	ErrClientURILen     = errors.New("client_uri is too long")
	ErrClientURIScheme  = errors.New("client_uri must be an ASCII http(s) URL with no userinfo")
	ErrAuthMethod       = errors.New(`only the "none" token endpoint auth method is supported; clients are public and use PKCE`)
)

// ValidateRedirectURI enforces what voodoo is willing to redirect a logged-in
// user's browser to after they approve a client.
//
// The security-relevant rule is the scheme: plaintext http is confined to
// loopback, because an authorization code in a redirect to a routable http address
// is a code handed to anyone on the path.
//
// This is a registration-time filter only. It does not decide which URI a given
// authorization request may use — /authorize exact-matches the requested
// redirect_uri against the registered set, so a client cannot widen its own
// targets after the fact.
func ValidateRedirectURI(raw string) error {
	if raw == "" || len(raw) > MaxURILen || strings.Contains(raw, "#") || !printableASCII(raw) {
		return ErrRedirectInvalid
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil {
		return ErrRedirectInvalid
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" {
			return ErrRedirectInvalid
		}
		return nil
	case "http":
		// RFC 8252 §7.3: native apps redirect to a loopback listener on a port they
		// cannot predict, so the host is what we check, never the port.
		if !isLoopbackHost(u.Hostname()) {
			return ErrRedirectInsecure
		}
		return nil
	default:
		// A private-use scheme (RFC 8252 §7.1) is how a desktop or mobile app
		// receives the redirect. The reverse-DNS convention — hence the required dot
		// — keeps an app from claiming a bare word like "app:" that any other app on
		// the machine might also register.
		if !strings.Contains(u.Scheme, ".") {
			return ErrRedirectInsecure
		}
		return nil
	}
}

// ValidateRedirectURIs validates a whole registration request's redirect_uris.
func ValidateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return ErrNoRedirectURIs
	}
	if len(uris) > MaxRedirectURIs {
		return ErrTooManyRedirects
	}
	for _, u := range uris {
		if err := ValidateRedirectURI(u); err != nil {
			return err
		}
	}
	return nil
}

// ValidateClientURI checks the optional homepage a client advertises. It becomes a
// link on the consent screen; html/template would refuse to emit a javascript:
// href anyway, but rejecting it here means the operator sees a real error instead
// of a mysteriously dead link.
func ValidateClientURI(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > MaxURILen {
		return ErrClientURILen
	}
	if !printableASCII(raw) {
		return ErrClientURIScheme
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ErrClientURIScheme
	}
	return nil
}

// printableASCII reports whether s is visible ASCII only. A URI shown on the
// consent screen must read the same to the user as to the browser: no homoglyphs,
// no bidi tricks, no spaces. Userinfo is refused for the same reason —
// "https://trusted.example@evil.example" names evil.example.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ValidateClientName bounds the one field a client gets to render on the consent
// screen, and supplies a placeholder when it names itself nothing at all. Control
// and format characters (Unicode Cc, Cf) are stripped: bidi overrides and
// zero-width characters let a name read differently from what it is.
func ValidateClientName(raw string) (string, error) {
	name := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return -1
		}
		return r
	}, raw))
	if name == "" {
		return "Unnamed client", nil
	}
	if len(name) > MaxClientNameLen {
		return "", ErrClientNameLen
	}
	return name, nil
}

// ValidateAuthMethod rejects secret-based client authentication now rather than at
// the client's first token request. Voodoo issues no client secrets.
func ValidateAuthMethod(method string) error {
	if method != "" && method != "none" {
		return ErrAuthMethod
	}
	return nil
}

// EncodeRedirectURIs joins registered URIs for storage in a single column.
// Newline is a safe separator because url.Parse rejects control characters.
func EncodeRedirectURIs(uris []string) string { return strings.Join(uris, "\n") }

// DecodeRedirectURIs is the inverse of EncodeRedirectURIs.
func DecodeRedirectURIs(stored string) []string {
	if stored == "" {
		return nil
	}
	return strings.Split(stored, "\n")
}

// RedirectURIAllowed reports whether requested exactly matches one of a client's
// registered URIs. Exact comparison is the point: loose redirect matching is the
// classic way an authorization code ends up delivered to an attacker's path on an
// otherwise legitimate host.
func RedirectURIAllowed(registered []string, requested string) bool {
	return slices.Contains(registered, requested)
}

// isLoopbackHost covers the whole loopback range, not just 127.0.0.1: RFC 8252
// §7.3 lets a native app listen anywhere in it.
func isLoopbackHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}
