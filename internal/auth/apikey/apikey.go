package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const Prefix = "ak_"

// Generate returns a fresh API key. raw is the user-facing token (shown once),
// hash is the SHA-256 hex digest stored in api_keys.hash, and prefix is the
// first 12 chars of raw for UI display.
func Generate() (raw, hash, prefix string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	raw = Prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, HashOf(raw), raw[:12], nil
}

// HashOf returns the SHA-256 hex digest of raw. Deterministic.
func HashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ParseBearer extracts the raw key from an Authorization header value. It
// accepts "Bearer <key>" (scheme is case-insensitive) where <key> begins with
// "ak_" and has no trailing whitespace.
func ParseBearer(authHeader string) (raw string, ok bool) {
	if len(authHeader) < 7 {
		return "", false
	}
	if !strings.EqualFold(authHeader[:7], "Bearer ") {
		return "", false
	}
	rest := authHeader[7:]
	if rest == "" || rest != strings.TrimSpace(rest) {
		return "", false
	}
	if !strings.HasPrefix(rest, Prefix) {
		return "", false
	}
	return rest, true
}
