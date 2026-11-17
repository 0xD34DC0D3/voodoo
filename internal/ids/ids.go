package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewID returns a 16-byte random ID encoded as lowercase base32 without padding.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(idEncoding.EncodeToString(b))
}

// NewToken returns a 32-byte random token encoded as base64url without padding
// (~43 chars). Use it wherever an unguessable secret is needed (session IDs,
// invite tokens).
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the SHA-256 hex digest of a NewToken value. The raw token
// goes to the user (cookie, invite link, reset link); only the digest is
// stored, so a leaked database yields nothing replayable. Unsalted on purpose:
// exact-match lookup needs determinism, and the input is 32 random bytes, not
// a password. Same scheme as internal/auth/apikey and internal/auth/oauth.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
