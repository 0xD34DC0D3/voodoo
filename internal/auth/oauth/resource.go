package oauth

import (
	"errors"
	"net/url"
	"strings"
)

// Resource indicators — RFC 8707. The client names the protected resource it
// intends to call, voodoo records it as the token's audience, and verification
// refuses to confirm the token to anyone else. Without it, a token minted for one
// app would be a working credential at every other app the same user can reach.
//
// Two policy choices narrow the RFC, both permitted by it (an authorization server
// may reject any target it is unwilling to serve, with invalid_target): exactly one
// resource per request, because a multi-audience token exceeds the blast radius of
// the request that created it; and a mandatory authority, so an audience is always a
// concrete network identity rather than an opaque URN whose equality rules we would
// have to invent.
var (
	ErrResourceMissing  = errors.New("resource parameter is required")
	ErrResourceMultiple = errors.New("exactly one resource parameter is allowed")
	ErrResourceInvalid  = errors.New("resource must be an absolute URI with no fragment")
)

// CanonicalResource validates a resource indicator and returns its canonical
// form. Canonicalization is what makes audience comparison meaningful: without
// it, "https://API.Example.com:443/mcp" and "https://api.example.com/mcp" would
// be different audiences, and a client could pick whichever spelling a resource
// server failed to expect.
func CanonicalResource(raw string) (string, error) {
	if raw == "" {
		return "", ErrResourceMissing
	}
	// A fragment is forbidden outright by RFC 8707 §2. Check the raw string
	// rather than the parsed fragment so that a bare trailing "#" — which parses
	// to an empty fragment — is rejected too.
	if strings.Contains(raw, "#") {
		return "", ErrResourceInvalid
	}

	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", ErrResourceInvalid
	}
	// Credentials are not part of an audience identifier, and permitting them
	// would give the same resource two spellings.
	if u.User != nil {
		return "", ErrResourceInvalid
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", ErrResourceInvalid
	}
	// Hostname() strips the brackets from an IPv6 literal, and without them back the
	// result is not a parseable URI — which would break the idempotence the audience
	// comparison relies on, since re-canonicalizing the stored value would not
	// return it unchanged.
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !isDefaultPort(scheme, port) {
		host += ":" + port
	}

	// A bare "/" carries no information, so fold it into the empty path. Any
	// deeper path is significant and kept as-is: "/mcp" and "/mcp/" address
	// different resources as far as we are concerned.
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}

	canonical := scheme + "://" + host + path
	if u.RawQuery != "" {
		canonical += "?" + u.RawQuery
	}
	return canonical, nil
}

// CanonicalResourceParam applies CanonicalResource to the repeated values of a
// single request parameter, enforcing the one-resource-per-request policy.
func CanonicalResourceParam(values []string) (string, error) {
	switch len(values) {
	case 0:
		return "", ErrResourceMissing
	case 1:
		return CanonicalResource(values[0])
	default:
		return "", ErrResourceMultiple
	}
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}
