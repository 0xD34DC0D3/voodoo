// Package session sets and reads the two cookies a browser session carries.
//
// CookieName is set on the parent domain (VOODOO_COOKIE_DOMAIN) so sibling apps
// can forward it to /me. It proves identity and nothing more: a sibling host, or
// a script injected into one, can hold it. Everything else voodoo serves to a
// cookie — its own pages, key minting, admin, OAuth consent — needs the UI
// cookie, which is host-only and carries an independent secret.
package session

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/config"
)

// CookieName is the parent-domain identity cookie sibling apps forward to /me.
const CookieName = "voodoo_session"

// UICookieName is the host-only cookie for voodoo's own routes. With secure
// cookies it takes the __Host- prefix, which makes the browser refuse it unless
// it is Secure, Path=/ and has no Domain — so no sibling host can set or
// shadow it.
func UICookieName(cfg *config.Config) string {
	if cfg.CookieSecure {
		return "__Host-voodoo_ui"
	}
	return "voodoo_ui"
}

// Set hands the browser both cookies: id for the parent domain, uiID for this
// host only.
func Set(c echo.Context, cfg *config.Config, id, uiID string, expiresAt time.Time) {
	c.SetCookie(cookie(CookieName, cfg.CookieDomain, id, expiresAt, cfg))
	c.SetCookie(cookie(UICookieName(cfg), "", uiID, expiresAt, cfg))
}

// Clear expires both cookies.
func Clear(c echo.Context, cfg *config.Config) {
	for _, ck := range []*http.Cookie{
		cookie(CookieName, cfg.CookieDomain, "", time.Unix(0, 0), cfg),
		cookie(UICookieName(cfg), "", "", time.Unix(0, 0), cfg),
	} {
		ck.MaxAge = -1
		c.SetCookie(ck)
	}
}

// Read returns the parent-domain cookie value, or "".
func Read(c echo.Context) string { return read(c, CookieName) }

// ReadUI returns the host-only UI cookie value, or "".
func ReadUI(c echo.Context, cfg *config.Config) string { return read(c, UICookieName(cfg)) }

func cookie(name, domain, value string, expires time.Time, cfg *config.Config) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func read(c echo.Context, name string) string {
	ck, err := c.Cookie(name)
	if err != nil || ck == nil {
		return ""
	}
	return ck.Value
}
