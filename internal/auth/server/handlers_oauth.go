package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
)

// authorizationCodeTTL is deliberately far below RFC 6749's 10-minute ceiling. A
// code is redeemed by the client within a second or two of the redirect; any
// longer window is pure exposure.
const authorizationCodeTTL = time.Minute

// issuer returns this deployment's OAuth issuer identifier. Clients compare it
// against the URL they fetched discovery metadata from (RFC 8414 §3.3), so it has
// to be the deployment's real public origin.
//
// The request-derived fallback exists only so the documented local-dev quickstart —
// which sets no VOODOO_BASE_URL — still serves coherent metadata.
func (s *Server) issuer(c echo.Context) string {
	if s.cfg.BaseURL != "" {
		return strings.TrimRight(s.cfg.BaseURL, "/")
	}
	return c.Scheme() + "://" + c.Request().Host
}

// resourceAllowed reports whether this deployment will mint tokens addressed to a
// canonical resource URI.
//
// The rule is the trust boundary the session cookie and post-login redirects
// already use: the parent domain and its subdomains, plus localhost when running
// insecure locally. Reusing it means there is one answer in voodoo to "which hosts
// are ours" rather than a second list to keep in sync.
//
// CookieDomain is empty for a single-host deployment, where the cookie is host-only
// and there are no sibling apps. Without its own answer there, hostInParentDomain
// trusts nothing and every authorization fails with invalid_target naming a resource
// that looks perfectly correct — so voodoo's own origin is the boundary instead.
func (s *Server) resourceAllowed(canonical string) bool {
	if !s.cfg.CookieSecure && hostIsLocalhost(canonical) {
		return true
	}
	if s.cfg.CookieDomain == "" {
		return s.cfg.BaseURL != "" && sameOrigin(canonical, s.cfg.BaseURL)
	}
	return hostInParentDomain(canonical, s.cfg.CookieDomain)
}

// sameOrigin reports whether a canonical resource URI shares scheme and host with
// base. Used only for the single-host case above.
func sameOrigin(canonical, base string) bool {
	cu, err := url.Parse(canonical)
	if err != nil {
		return false
	}
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return false
	}
	return strings.EqualFold(cu.Scheme, bu.Scheme) && strings.EqualFold(cu.Host, bu.Host)
}

// checkResource validates a request's resource indicator all the way through
// policy, returning the canonical audience or the error to report to the client.
func (s *Server) checkResource(values []string) (canonical string, fail *oauth.ErrorBody) {
	canonical, err := oauth.CanonicalResourceParam(values)
	if err != nil {
		return "", &oauth.ErrorBody{Code: oauth.ResourceErrorCode(err), Description: err.Error()}
	}
	if !s.resourceAllowed(canonical) {
		// Deliberately specific: an operator misconfiguring a resource server's
		// canonical URI is far more likely than an attacker probing for it, and this
		// is the error they will be staring at.
		return "", &oauth.ErrorBody{
			Code:        oauth.ErrCodeInvalidTarget,
			Description: "this authorization server does not issue tokens for " + canonical,
		}
	}
	return canonical, nil
}

// bodyParams returns the POST body's form parameters only. echo's FormParams and
// r.Form merge in the query string, which would let credentials such as codes and
// tokens travel in URLs, where proxies, logs and Referer headers keep them.
func bodyParams(c echo.Context) (url.Values, error) {
	r := c.Request()
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return r.PostForm, nil
}

// oauthError writes an RFC 6749 §5.2 style JSON error.
func oauthError(c echo.Context, status int, code, desc string) error {
	return c.JSON(status, oauth.ErrorBody{Code: code, Description: desc})
}

func oauthErrorBody(c echo.Context, status int, body *oauth.ErrorBody) error {
	return c.JSON(status, body)
}

// noStoreMiddleware keeps a response out of caches. It covers every OAuth endpoint,
// wired once in oauthRoutes rather than called per handler: these responses carry
// credentials in bodies *and* in Location headers, and the one that matters most —
// the /authorize redirect holding a fresh authorization code — is the easiest to
// forget. It also covers the routes that show a freshly minted API key, reset link
// or invite link.
func noStoreMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := c.Response().Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		return next(c)
	}
}

// --- Discovery (RFC 8414) ---

type asMetadata struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	RegistrationEndpoint                   string   `json:"registration_endpoint"`
	IntrospectionEndpoint                  string   `json:"introspection_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	ScopesSupported                        []string `json:"scopes_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	AuthorizationResponseIssParamSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (s *Server) getOAuthMetadata(c echo.Context) error {
	iss := s.issuer(c)
	return c.JSON(http.StatusOK, asMetadata{
		Issuer:                        iss,
		AuthorizationEndpoint:         iss + "/authorize",
		TokenEndpoint:                 iss + "/token",
		RegistrationEndpoint:          iss + "/register",
		IntrospectionEndpoint:         iss + "/introspect",
		RevocationEndpoint:            iss + "/revoke",
		ScopesSupported:               oauth.SupportedScopes(),
		ResponseTypesSupported:        []string{responseTypeCode},
		GrantTypesSupported:           []string{grantAuthorizationCode, grantRefreshToken},
		CodeChallengeMethodsSupported: []string{oauth.MethodS256},
		// Every client is public: voodoo issues no client secrets, so PKCE rather
		// than client authentication is what binds a code to its requester.
		TokenEndpointAuthMethodsSupported:      []string{authMethodNone},
		RevocationEndpointAuthMethodsSupported: []string{authMethodNone},
		// RFC 9207: the authorization response carries iss so a client juggling
		// several authorization servers cannot be tricked into redeeming a code at
		// the wrong one.
		AuthorizationResponseIssParamSupported: true,
	})
}

// --- Dynamic client registration (RFC 7591) ---

const (
	responseTypeCode = "code"
	authMethodNone   = "none"
)

type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientURI               string   `json:"client_uri"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientURI               string   `json:"client_uri,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// postRegister implements dynamic client registration. It is unauthenticated,
// which is the whole point — an MCP client that has never met this server needs a
// client_id before it can start a flow.
//
// Registering therefore grants nothing. A row in oauth_clients means "some software
// asked for an ID", and the only thing it confers is the ability to render a
// self-reported client_name on a consent screen the user must still read and
// approve. Authorization happens there, per request, never here.
func (s *Server) postRegister(c echo.Context) error {
	var req registerRequest
	if err := c.Bind(&req); err != nil {
		return oauthError(c, http.StatusBadRequest, oauth.ErrCodeInvalidMetadata,
			"request body must be JSON")
	}

	name, err := validateRegistration(&req)
	if err != nil {
		return oauthError(c, http.StatusBadRequest, registrationErrorCode(err), err.Error())
	}

	cl, err := s.q.CreateOAuthClient(c.Request().Context(), store.CreateOAuthClientParams{
		ID:           oauth.NewClientID(),
		Name:         name,
		RedirectUris: oauth.EncodeRedirectURIs(req.RedirectURIs),
		ClientUri:    nullString(strings.TrimSpace(req.ClientURI)),
	})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, registerResponse{
		ClientID:                cl.ID,
		ClientIDIssuedAt:        cl.CreatedAt.Unix(),
		ClientName:              cl.Name,
		RedirectURIs:            oauth.DecodeRedirectURIs(cl.RedirectUris),
		ClientURI:               cl.ClientUri.String,
		GrantTypes:              []string{grantAuthorizationCode, grantRefreshToken},
		ResponseTypes:           []string{responseTypeCode},
		TokenEndpointAuthMethod: authMethodNone,
		Scope:                   strings.Join(oauth.SupportedScopes(), " "),
	})
}

// validateRegistration applies every registration-time rule and returns the
// client_name to store.
func validateRegistration(req *registerRequest) (name string, err error) {
	if err := oauth.ValidateRedirectURIs(req.RedirectURIs); err != nil {
		return "", err
	}
	if err := oauth.ValidateAuthMethod(req.TokenEndpointAuthMethod); err != nil {
		return "", err
	}
	if err := requireSubset("grant_types", req.GrantTypes, []string{grantAuthorizationCode, grantRefreshToken}); err != nil {
		return "", err
	}
	if err := requireSubset("response_types", req.ResponseTypes, []string{responseTypeCode}); err != nil {
		return "", err
	}
	if err := oauth.ValidateClientURI(strings.TrimSpace(req.ClientURI)); err != nil {
		return "", err
	}
	return oauth.ValidateClientName(req.ClientName)
}

// registrationErrorCode maps a rejection to its RFC 7591 §3.2.2 error code. Only a
// malformed redirect_uri gets the dedicated code; an absent one is missing metadata
// rather than bad metadata.
func registrationErrorCode(err error) string {
	switch {
	case errors.Is(err, oauth.ErrNoRedirectURIs):
		return oauth.ErrCodeInvalidMetadata
	case errors.Is(err, oauth.ErrTooManyRedirects),
		errors.Is(err, oauth.ErrRedirectInsecure),
		errors.Is(err, oauth.ErrRedirectInvalid):
		return oauth.ErrCodeInvalidRedirectURI
	default:
		return oauth.ErrCodeInvalidMetadata
	}
}

// requireSubset checks that every value in got is allowed. An empty got means the
// client expressed no preference, which is fine — it gets the defaults.
func requireSubset(field string, got, allowed []string) error {
	for _, v := range got {
		if !slices.Contains(allowed, v) {
			return fmt.Errorf("%s: unsupported value %q; supported: %s",
				field, v, strings.Join(allowed, ", "))
		}
	}
	return nil
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
