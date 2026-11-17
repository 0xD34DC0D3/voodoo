package oauth

import (
	"strings"
	"testing"
)

// The one vector from RFC 7636 Appendix B, so a refactor of the encoding can't
// quietly produce challenges that no real client would agree with.
func TestChallengeFromVerifierRFC7636Vector(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := ChallengeFromVerifier(verifier); got != challenge {
		t.Fatalf("ChallengeFromVerifier() = %q, want %q", got, challenge)
	}
	if !VerifyS256(verifier, challenge) {
		t.Fatal("VerifyS256 rejected the RFC 7636 vector")
	}
}

func TestVerifyS256(t *testing.T) {
	verifier := strings.Repeat("a", 64)
	challenge := ChallengeFromVerifier(verifier)

	if !VerifyS256(verifier, challenge) {
		t.Fatal("matching verifier rejected")
	}
	if VerifyS256(strings.Repeat("b", 64), challenge) {
		t.Fatal("wrong verifier accepted")
	}
	// A verifier that fails the grammar must fail closed even if some other
	// encoding of it would hash to the stored challenge.
	if VerifyS256("short", ChallengeFromVerifier("short")) {
		t.Fatal("out-of-grammar verifier accepted")
	}
	if VerifyS256("", "") {
		t.Fatal("empty verifier accepted")
	}
	// The stored challenge is never treated as a prefix.
	if VerifyS256(verifier, challenge[:len(challenge)-1]) {
		t.Fatal("truncated challenge accepted")
	}
}

func TestValidVerifier(t *testing.T) {
	valid := []string{
		strings.Repeat("a", 43),
		strings.Repeat("a", 128),
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		strings.Repeat("-._~", 11), // 44 chars, all unreserved punctuation
	}
	for _, v := range valid {
		if !ValidVerifier(v) {
			t.Fatalf("ValidVerifier(%q) = false, want true", v)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("a", 42),  // one short of the minimum
		strings.Repeat("a", 129), // one past the maximum
		strings.Repeat("a", 42) + "+",
		strings.Repeat("a", 42) + "/",
		strings.Repeat("a", 42) + "=",
		strings.Repeat("a", 42) + " ",
		strings.Repeat("a", 42) + "\n",
		strings.Repeat("a", 42) + "é",
	}
	for _, v := range invalid {
		if ValidVerifier(v) {
			t.Fatalf("ValidVerifier(%q) = true, want false", v)
		}
	}
}

func TestValidChallenge(t *testing.T) {
	good := ChallengeFromVerifier(strings.Repeat("a", 64))
	if !ValidChallenge(good) {
		t.Fatalf("ValidChallenge(%q) = false, want true", good)
	}

	bad := []string{
		"",
		good[:42],  // too short
		good + "A", // too long
		strings.Repeat("=", 43),
		strings.Repeat("+", 43),
		strings.Repeat("/", 43),
	}
	for _, s := range bad {
		if ValidChallenge(s) {
			t.Fatalf("ValidChallenge(%q) = true, want false", s)
		}
	}
}
