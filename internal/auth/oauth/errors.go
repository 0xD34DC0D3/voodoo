package oauth

import "errors"

// Protocol error codes. Spelled out as constants because clients branch on these
// strings — a typo here is a client that cannot tell "try again with a different
// scope" from "your code expired".
const (
	ErrCodeInvalidRequest       = "invalid_request"         // RFC 6749 §4.1.2.1 / §5.2
	ErrCodeInvalidClient        = "invalid_client"          // RFC 6749 §5.2
	ErrCodeInvalidGrant         = "invalid_grant"           // RFC 6749 §5.2
	ErrCodeUnauthorizedClient   = "unauthorized_client"     // RFC 6749 §4.1.2.1
	ErrCodeUnsupportedGrantType = "unsupported_grant_type"  // RFC 6749 §5.2
	ErrCodeInvalidScope         = "invalid_scope"           // RFC 6749 §5.2
	ErrCodeAccessDenied         = "access_denied"           // RFC 6749 §4.1.2.1
	ErrCodeServerError          = "server_error"            // RFC 6749 §4.1.2.1
	ErrCodeInvalidTarget        = "invalid_target"          // RFC 8707 §2
	ErrCodeInvalidRedirectURI   = "invalid_redirect_uri"    // RFC 7591 §3.2.2
	ErrCodeInvalidMetadata      = "invalid_client_metadata" // RFC 7591 §3.2.2
)

// ErrorBody is the JSON error shape shared by the token, registration,
// introspection, and revocation endpoints (RFC 6749 §5.2, RFC 7591 §3.2.2).
type ErrorBody struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// ResourceErrorCode maps a resource-indicator validation failure to its protocol
// error code. RFC 8707 defines invalid_target for a target the server will not
// or cannot serve; a request with no resource at all is a malformed request
// instead, since voodoo requires the parameter.
func ResourceErrorCode(err error) string {
	if errors.Is(err, ErrResourceMissing) {
		return ErrCodeInvalidRequest
	}
	return ErrCodeInvalidTarget
}
