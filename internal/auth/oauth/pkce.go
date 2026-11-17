package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCE (RFC 7636). Only the S256 method is supported: "plain" offers no
// protection against an attacker who can read the authorization request, and
// OAuth 2.1 forbids it for public clients. Because every voodoo client is public,
// PKCE is the sole proof that whoever redeems a code is who requested it.
const MethodS256 = "S256"

// challengeLen is the length of a base64url-encoded SHA-256 digest, which is
// exactly what a well-formed S256 challenge is.
const challengeLen = 43

// ValidChallenge reports whether s is a syntactically valid S256 code challenge.
// Enforcing the exact shape here means a client cannot smuggle in a short,
// low-entropy challenge and weaken the flow.
func ValidChallenge(s string) bool {
	if len(s) != challengeLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// ValidVerifier reports whether s satisfies RFC 7636's code_verifier grammar:
// 43–128 characters drawn from the unreserved set.
func ValidVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// ChallengeFromVerifier returns the S256 challenge for verifier:
// BASE64URL(SHA256(ASCII(verifier))), unpadded.
func ChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyS256 reports whether verifier hashes to challenge. The comparison is
// constant-time: the challenge is stored server-side and a timing oracle on it
// would let an attacker who holds a code recover the value needed to redeem it.
func VerifyS256(verifier, challenge string) bool {
	if !ValidVerifier(verifier) {
		return false
	}
	got := ChallengeFromVerifier(verifier)
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
