package server

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/password"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

// invalidResetErr is deliberately vague: the reset page is public, so it must
// not reveal whether a token ever existed, only that this one won't work.
const invalidResetErr = "this reset link is invalid, expired, or already used"

type resetView struct {
	web.Chrome
	Error string
	// Token is echoed into a hidden field so the POST can re-find the row. It is
	// empty when the link is unusable, which hides the form (see reset.html).
	Token string
}

func (s *Server) resetView(c echo.Context, errMsg, token string) resetView {
	return resetView{Chrome: s.pageChrome(c, "reset password"), Error: errMsg, Token: token}
}

func (s *Server) getReset(c echo.Context) error {
	token := c.QueryParam("token")
	if _, err := s.lookupReset(c, token); err != nil {
		return s.render(c, http.StatusBadRequest, "reset.html",
			s.resetView(c, invalidResetErr, ""))
	}
	return s.render(c, http.StatusOK, "reset.html", s.resetView(c, "", token))
}

func (s *Server) postReset(c echo.Context) error {
	token := c.FormValue("token")
	pw := c.FormValue("password")
	confirm := c.FormValue("confirm")

	// Re-validate before doing any work; the row may have expired or been used
	// since the form was served.
	if _, err := s.lookupReset(c, token); err != nil {
		return s.render(c, http.StatusBadRequest, "reset.html",
			s.resetView(c, invalidResetErr, ""))
	}
	if pw == "" {
		return s.render(c, http.StatusBadRequest, "reset.html",
			s.resetView(c, "password is required", token))
	}
	if err := password.CheckNew(pw); err != nil {
		return s.render(c, http.StatusBadRequest, "reset.html",
			s.resetView(c, err.Error(), token))
	}
	if pw != confirm {
		return s.render(c, http.StatusBadRequest, "reset.html",
			s.resetView(c, "passwords do not match", token))
	}

	hash, err := s.hashPassword(c, pw)
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qtx := s.q.WithTx(tx)

	// ConsumePasswordReset is the atomic gate: it only matches an unused,
	// unexpired row, so a racing second submit can't pass. ExpiresAt below is
	// the "expires_at > ?" threshold, not a new expiry.
	now := time.Now().UTC()
	userID, err := qtx.ConsumePasswordReset(ctx, store.ConsumePasswordResetParams{
		UsedAt:    sql.NullTime{Time: now, Valid: true},
		Token:     ids.HashToken(token),
		ExpiresAt: now,
	})
	if err != nil {
		return s.render(c, http.StatusBadRequest, "reset.html",
			s.resetView(c, invalidResetErr, ""))
	}
	if err := qtx.UpdateUserPassword(ctx, store.UpdateUserPasswordParams{
		PasswordHash: hash,
		ID:           userID,
	}); err != nil {
		return err
	}
	// A password reset must boot anyone already signed in — including an attacker
	// whose access prompted the reset — so every credential goes, not just sessions.
	if err := revokeAllCredentials(ctx, qtx, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	logEvent(c, "auth.password_reset", "user", userID)

	s.setFlash(c, "Password updated — please log in.")
	return c.Redirect(http.StatusFound, "/login")
}

// lookupReset returns the reset row if the token references an unused,
// unexpired reset, otherwise an error. Mirrors lookupInvite.
func (s *Server) lookupReset(c echo.Context, token string) (store.PasswordReset, error) {
	if token == "" {
		return store.PasswordReset{}, errors.New("missing token")
	}
	pr, err := s.q.GetPasswordResetByToken(c.Request().Context(), ids.HashToken(token))
	if err != nil {
		return store.PasswordReset{}, err
	}
	if pr.UsedAt.Valid {
		return store.PasswordReset{}, errors.New("already used")
	}
	if !pr.ExpiresAt.After(time.Now().UTC()) {
		return store.PasswordReset{}, errors.New("expired")
	}
	return pr, nil
}
