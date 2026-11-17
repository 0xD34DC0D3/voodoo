package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// ctxLogErrKey carries an error a handler answered 500 for without returning
// it (oauthServerError, healthz), so the request line can still show it.
const ctxLogErrKey = "log_err"

// requestLogger writes one line per request: method, route pattern, status,
// duration. It logs the route pattern (/admin/users/:id/disable), never the
// URL: query strings and paths here carry codes, tokens and reset links.
// A 5xx line also carries the error.
func requestLogger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		if err != nil {
			// Let echo turn the error into a response now so the status is final.
			c.Error(err)
		}
		status := c.Response().Status
		attrs := []any{
			"method", c.Request().Method,
			"route", routePattern(c),
			"status", status,
			"dur_ms", time.Since(start).Milliseconds(),
		}
		if status >= http.StatusInternalServerError {
			if err == nil {
				err, _ = c.Get(ctxLogErrKey).(error)
			}
			slog.Error("request", append(attrs, "err", err)...)
		} else {
			slog.Info("request", attrs...)
		}
		return nil
	}
}

// routePattern is the matched route, or a fixed label when nothing matched
// (echo then reports the raw path, which must not be logged).
func routePattern(c echo.Context) string {
	p := c.Path()
	for _, r := range c.Echo().Routes() {
		if r.Path == p {
			return p
		}
	}
	return "unmatched"
}

// logEvent records an auth or admin event. Callers pass ids only: never
// passwords, tokens, links or email addresses.
func logEvent(c echo.Context, event string, attrs ...any) {
	if u, ok := UserFromContext(c); ok {
		attrs = append(attrs, "actor", u.ID)
	}
	slog.Info(event, attrs...)
}

// auditAdmin logs every admin write that succeeded (status below 400) as
// "admin.<action>", with the acting admin and the target from the route.
func auditAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err != nil || c.Request().Method != http.MethodPost || c.Response().Status >= 400 {
			return err
		}
		var attrs []any
		if id := c.Param("id"); id != "" {
			attrs = append(attrs, "target", id)
		}
		if tok := c.Param("token"); tok != "" {
			attrs = append(attrs, "target", tokenPreview(tok))
		}
		logEvent(c, "admin."+adminAction(c.Path()), attrs...)
		return nil
	}
}

// adminAction names an admin route: /admin/users/:id/sessions/revoke ->
// users.sessions.revoke, /admin/invites -> invites.create.
func adminAction(path string) string {
	var parts []string
	for _, p := range strings.Split(strings.TrimPrefix(path, "/admin/"), "/") {
		if p != "" && !strings.HasPrefix(p, ":") {
			parts = append(parts, p)
		}
	}
	if len(parts) == 1 {
		parts = append(parts, "create")
	}
	return strings.Join(parts, ".")
}
