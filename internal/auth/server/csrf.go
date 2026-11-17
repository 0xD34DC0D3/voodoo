package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// crossOriginMiddleware rejects cross-origin browser requests on unsafe methods
// (CSRF), using the stdlib's Sec-Fetch-Site / Origin check. Requests that carry
// neither header — curl, servers, anything holding an API key — pass, which is
// right: they hold no ambient cookie a third-party page could borrow.
//
// The OAuth machine endpoints are bypassed: clients call them cross-origin by
// design and authenticate with a code, refresh token, client id or API key,
// never a cookie.
//
// POST /logout additionally accepts a same-site post from a sibling host of
// this deployment (the cookie domain): sibling apps host the logout form. It is
// the only cookie route a sibling may drive; logout can only end the session,
// and every other route needs the host-only UI cookie besides.
func (s *Server) crossOriginMiddleware() echo.MiddlewareFunc {
	cop := http.NewCrossOriginProtection()
	for _, p := range []string{"/token", "/register", "/introspect", "/revoke"} {
		cop.AddInsecureBypassPattern(p)
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			if err := cop.Check(req); err != nil && !s.siblingLogout(req) {
				return c.String(http.StatusForbidden, "cross-origin request rejected")
			}
			return next(c)
		}
	}
}

// siblingLogout reports whether req is a logout posted from a sibling host:
// an Origin on the cookie's parent domain (https), or localhost in insecure
// local dev — the same hosts safeNext lets a login bounce back to.
func (s *Server) siblingLogout(req *http.Request) bool {
	if req.Method != http.MethodPost || req.URL.Path != "/logout" {
		return false
	}
	origin := req.Header.Get("Origin")
	if origin == "" {
		return false
	}
	return hostInParentDomain(origin, s.cfg.CookieDomain) ||
		(!s.cfg.CookieSecure && hostIsLocalhost(origin))
}
