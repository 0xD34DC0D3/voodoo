package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/password"
)

// hashWait is how long a request waits for the argon2 slot before giving up.
const hashWait = 5 * time.Second

// Every argon2 call takes 64 MiB and most of a core. Unbounded, a burst of
// logins is a memory exhaustion attack on a small host, so all hashing and
// verification share one slot. Waiters that cannot get it in time get 503
// rather than piling up.

// withHashSlot runs fn while holding the argon2 slot. It returns a 503 error if
// the slot does not free up within s.hashWait or the request goes away first.
func (s *Server) withHashSlot(c echo.Context, fn func()) error {
	t := time.NewTimer(s.hashWait)
	defer t.Stop()
	select {
	case s.hashSlot <- struct{}{}:
	case <-t.C:
		return hashBusy(c)
	case <-c.Request().Context().Done():
		return hashBusy(c)
	}
	defer func() { <-s.hashSlot }()
	fn()
	return nil
}

func hashBusy(c echo.Context) error {
	c.Response().Header().Set("Retry-After", "5")
	return echo.NewHTTPError(http.StatusServiceUnavailable, "server busy; try again shortly")
}

// hashPassword is password.Hash under the argon2 slot.
func (s *Server) hashPassword(c echo.Context, plain string) (string, error) {
	var (
		hash string
		err  error
	)
	if slotErr := s.withHashSlot(c, func() { hash, err = password.Hash(plain) }); slotErr != nil {
		return "", slotErr
	}
	return hash, err
}

// verifyPassword is password.Verify under the argon2 slot.
func (s *Server) verifyPassword(c echo.Context, encoded, plain string) (bool, error) {
	var (
		ok  bool
		err error
	)
	if slotErr := s.withHashSlot(c, func() { ok, err = password.Verify(encoded, plain) }); slotErr != nil {
		return false, slotErr
	}
	return ok, err
}

// isHashBusy reports whether err is the 503 from withHashSlot, as opposed to a
// verification error that the login path folds into a generic failure.
func isHashBusy(err error) bool {
	var he *echo.HTTPError
	return errors.As(err, &he) && he.Code == http.StatusServiceUnavailable
}
