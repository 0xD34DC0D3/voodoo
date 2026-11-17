package server

import "github.com/labstack/echo/v4"

// contentSecurityPolicy allows only voodoo's own static assets: no inline
// script or style, no framing. It sets no form-action — the consent form's
// response redirects to the client's redirect URI, which form-action would block.
const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"

// securityHeaders sets the browser hardening headers on every response.
func securityHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := c.Response().Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		return next(c)
	}
}
