package oauth

import (
	"slices"
	"strings"
)

// ScopeIdentity is the only scope voodoo grants: a token says who the user is and
// nothing more, exactly like the API keys that predate it. Every downstream app
// already trusts any authenticated user, so finer-grained scopes would advertise a
// distinction the system does not enforce — worse than having none.
const ScopeIdentity = "voodoo:identity"

// SupportedScopes returns a fresh slice so a caller cannot mutate the policy.
func SupportedScopes() []string {
	return []string{ScopeIdentity}
}

// ScopeDescriptions renders a space-delimited scope string as the sentences shown
// on the consent screen.
func ScopeDescriptions(scope string) []string {
	fields := strings.Fields(scope)
	out := make([]string, 0, len(fields))
	for _, sc := range fields {
		out = append(out, describeScope(sc))
	}
	return out
}

// describeScope stays total so a scope added to SupportedScopes and forgotten here
// degrades to its own name rather than a blank row.
func describeScope(scope string) string {
	if scope == ScopeIdentity {
		return "See who you are: your user ID, email address, and timezone."
	}
	return scope
}

// Grant resolves a requested scope string against what this deployment supports,
// downscoping rather than failing wherever it can — permitted by RFC 6749 §3.3
// provided the granted scope is echoed back, which the token response always does.
//
// ok is false only when the client asked exclusively for scopes we do not support.
// Issuing an identity token then would answer a question it did not pose.
func Grant(requested string) (granted string, ok bool) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return strings.Join(SupportedScopes(), " "), true
	}
	supported := SupportedScopes()
	var kept []string
	for _, want := range fields {
		// Scope tokens are case-sensitive per RFC 6749 §3.3.
		if slices.Contains(supported, want) && !slices.Contains(kept, want) {
			kept = append(kept, want)
		}
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, " "), true
}

// Narrow returns requested when every scope in it was already granted. A refresh
// may narrow scope but never widen it (RFC 6749 §6); an empty request keeps what
// was granted.
func Narrow(granted, requested string) (narrowed string, ok bool) {
	want := strings.Fields(requested)
	if len(want) == 0 {
		return granted, true
	}
	have := strings.Fields(granted)
	for _, w := range want {
		if !slices.Contains(have, w) {
			return "", false
		}
	}
	return strings.Join(want, " "), true
}
