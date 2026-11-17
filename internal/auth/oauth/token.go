// Package oauth holds the pure, storage-free pieces of voodoo's OAuth 2.1
// authorization server: secret generation, PKCE, scope policy, RFC 8707 resource
// indicators, and client-registration validation. Everything here is a function
// of its arguments; the HTTP handlers and SQL live in the server package.
package oauth

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

// Secret prefixes. They exist so a leaked string is identifiable on sight and so
// the token endpoint can tell an access token from a refresh token before touching
// the database.
const (
	ClientIDPrefix     = "vc_"
	CodePrefix         = "vac_"
	AccessTokenPrefix  = "vat_"
	RefreshTokenPrefix = "vrt_"
)

// NewSecret returns a fresh random secret carrying prefix, along with the digest
// stored in its place. Only the hash is persisted, so a database read cannot be
// replayed as a credential.
func NewSecret(prefix string) (raw, hash string) {
	raw = prefix + ids.NewToken()
	return raw, HashOf(raw)
}

// HashOf returns the SHA-256 hex digest of raw. Same scheme as
// internal/auth/apikey — these are all high-entropy random secrets, so a slow
// password hash would buy nothing.
func HashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// NewClientID returns an identifier for a dynamically registered client. Unlike
// the secrets above it is not confidential, but it must still be unguessable so
// one client cannot impersonate another.
func NewClientID() string {
	return ClientIDPrefix + ids.NewID()
}
