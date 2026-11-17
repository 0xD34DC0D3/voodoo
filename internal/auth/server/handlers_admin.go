package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

const (
	defaultInviteDays = 7
	maxInviteDays     = 365

	// passwordResetTTL is how long an admin-issued reset link stays valid. Kept
	// short because the link is a bearer secret: anyone holding it can set the
	// account's password. The reset.html copy must echo this duration.
	passwordResetTTL = time.Hour
)

type adminUserRow struct {
	ID       string
	Email    string
	IsAdmin  bool
	Disabled bool
	Created  string
	IsSelf   bool
}

type adminUsersView struct {
	web.Chrome
	Error string
	Users []adminUserRow
	// ResetLink is a freshly minted, one-time password-reset link shown once
	// after issuing it; ResetEmail names the account it belongs to. Both empty
	// on a normal page load.
	ResetLink  string
	ResetEmail string
}

type adminInviteRow struct {
	// Token is the stored digest (the row key, used by the delete form), not
	// the invite link, which is shown once at creation.
	Token        string
	TokenPreview string
	// Email is the bound address; empty for an open invite.
	Email  string
	Status string
	// Signups counts accounts created from the invite; SignupEmails lists them.
	Signups      int64
	SignupEmails string
	Expires      string
	Created      string
}

type adminInvitesView struct {
	web.Chrome
	Error   string
	NewLink string
	Invites []adminInviteRow
	// submitted values, re-populated into the create form after a validation
	// error (FormDays also carries the default on a fresh load)
	FormEmail string
	FormDays  string
}

const ctxTargetUserKey = "target_user"

// requireTargetUser loads the user named by :id for an admin action and answers
// 404 when there is none. Without it, an update or delete against an unknown id
// matches no rows and the handler reports success.
func (s *Server) requireTargetUser(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		u, err := s.q.GetUserByID(c.Request().Context(), c.Param("id"))
		if errors.Is(err, sql.ErrNoRows) {
			return s.renderAdminUsers(c, http.StatusNotFound, "user not found", "", "")
		}
		if err != nil {
			return err
		}
		c.Set(ctxTargetUserKey, &u)
		return next(c)
	}
}

func (s *Server) getAdmin(c echo.Context) error {
	return s.render(c, http.StatusOK, "admin.html", struct{ web.Chrome }{s.pageChrome(c, "admin")})
}

func (s *Server) getAdminUsers(c echo.Context) error {
	return s.renderAdminUsers(c, http.StatusOK, "", "", "")
}

func (s *Server) renderAdminUsers(c echo.Context, status int, errMsg, resetLink, resetEmail string) error {
	me, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	users, err := s.q.ListUsers(c.Request().Context())
	if err != nil {
		return err
	}
	rows := make([]adminUserRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, adminUserRow{
			ID:       u.ID,
			Email:    u.Email,
			IsAdmin:  u.IsAdmin,
			Disabled: u.DisabledAt.Valid,
			Created:  timeStr(u.CreatedAt),
			IsSelf:   u.ID == me.ID,
		})
	}
	return s.render(c, status, "admin_users.html", adminUsersView{
		Chrome: s.pageChrome(c, "users"), Error: errMsg, Users: rows,
		ResetLink: resetLink, ResetEmail: resetEmail,
	})
}

func (s *Server) postAdminUserDisable(c echo.Context) error {
	me, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	id := c.Param("id")
	if id == me.ID {
		return s.renderAdminUsers(c, http.StatusBadRequest, "you cannot disable yourself", "", "")
	}

	ctx := c.Request().Context()
	if err := s.inTx(ctx, func(q *store.Queries) error {
		if err := q.DisableUser(ctx, store.DisableUserParams{
			DisabledAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
			ID:         id,
		}); err != nil {
			return err
		}
		// Disabling a user must immediately cut their live credentials; otherwise an
		// open browser tab — or a token in some other app's memory — keeps working
		// until the row expires naturally.
		return revokeAllCredentials(ctx, q, id)
	}); err != nil {
		return err
	}
	s.setFlash(c, "User disabled — their sessions, API keys and connected apps were revoked.")
	return c.Redirect(http.StatusFound, "/admin/users")
}

// postAdminUserEnable clears disabled_at. Nothing else comes back: disabling
// deleted every credential, so the user logs in again and re-mints any keys.
func (s *Server) postAdminUserEnable(c echo.Context) error {
	if err := s.q.EnableUser(c.Request().Context(), c.Param("id")); err != nil {
		return err
	}
	s.setFlash(c, "User re-enabled.")
	return c.Redirect(http.StatusFound, "/admin/users")
}

// postAdminUserRevokeSessions is the non-destructive "kick this account out" button,
// so it has to cut every credential a compromised session could have minted — not
// just the session. An attacker who used their window to authorize an OAuth client of
// their own would otherwise keep working access for the full refresh lifetime while
// the admin reads "Sessions revoked." and believes the account contained.
func (s *Server) postAdminUserRevokeSessions(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	if err := s.inTx(ctx, func(q *store.Queries) error {
		return revokeAllCredentials(ctx, q, id)
	}); err != nil {
		return err
	}

	s.setFlash(c, "Sessions, API keys and connected apps revoked.")
	return c.Redirect(http.StatusFound, "/admin/users")
}

// revokeAllCredentials cuts every way a user can currently authenticate: sessions,
// API keys, OAuth tokens, and unredeemed authorization codes.
//
// It is one function because it is one decision. "Lock this account out" is what
// disabling, an admin session revoke, and a password reset all mean, and a caller
// that revokes only sessions leaves a token alive in some other app's memory for the
// full refresh lifetime — where no admin can see it. API keys go too: a session an
// attacker held could have minted one, and it never expires on its own. Codes count
// as well: an unredeemed code is still worth a full-lifetime grant, so leaving one
// behind makes the revocation reversible.
func revokeAllCredentials(ctx context.Context, q *store.Queries, userID string) error {
	if err := q.DeleteSessionsByUser(ctx, userID); err != nil {
		return err
	}
	if err := q.DeleteApiKeysByUser(ctx, userID); err != nil {
		return err
	}
	if err := q.DeleteOAuthTokensByUser(ctx, userID); err != nil {
		return err
	}
	return q.DeleteOAuthCodesByUser(ctx, userID)
}

func (s *Server) postAdminUserPromote(c echo.Context) error {
	return s.setUserAdmin(c, true, "User promoted to admin.")
}

func (s *Server) postAdminUserDemote(c echo.Context) error {
	me, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	// Prevent admin lockout via the web UI: an admin can't demote themselves.
	// CLI `voodoo admin demote` is unrestricted (local operator, trusted).
	if c.Param("id") == me.ID {
		return s.renderAdminUsers(c, http.StatusBadRequest, "you cannot demote yourself", "", "")
	}
	return s.setUserAdmin(c, false, "User demoted to user.")
}

func (s *Server) setUserAdmin(c echo.Context, isAdmin bool, flash string) error {
	if err := s.q.SetUserAdmin(c.Request().Context(), store.SetUserAdminParams{
		IsAdmin: isAdmin,
		ID:      c.Param("id"),
	}); err != nil {
		return err
	}
	s.setFlash(c, flash)
	return c.Redirect(http.StatusFound, "/admin/users")
}

// postAdminUserReset mints a one-time password-reset link for a user and shows
// it once, mirroring the invite flow: voodoo sends no email, so the admin hands
// the link to the user out-of-band. Issuing a new link invalidates any earlier
// unused link for the same account, so only the most recent one works.
func (s *Server) postAdminUserReset(c echo.Context) error {
	me, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	u := c.Get(ctxTargetUserKey).(*store.User)
	id := u.ID

	ctx := c.Request().Context()

	// token goes in the link; password_resets.token holds only its digest.
	token := ids.NewToken()
	expires := time.Now().UTC().Add(passwordResetTTL)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qtx := s.q.WithTx(tx)
	if err := qtx.DeletePasswordResetsByUser(ctx, id); err != nil {
		return err
	}
	if _, err := qtx.CreatePasswordReset(ctx, store.CreatePasswordResetParams{
		Token:     ids.HashToken(token),
		UserID:    id,
		CreatedBy: me.ID,
		ExpiresAt: expires,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	return s.renderAdminUsers(c, http.StatusOK, "", s.absLink("/reset", "token", token), u.Email)
}

func (s *Server) getAdminInvites(c echo.Context) error {
	return s.renderAdminInvites(c, http.StatusOK, "", "", "", strconv.Itoa(defaultInviteDays))
}

func (s *Server) renderAdminInvites(c echo.Context, status int, errMsg, newLink, formEmail, formDays string) error {
	invites, err := s.q.ListInvites(c.Request().Context())
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	rows := make([]adminInviteRow, 0, len(invites))
	for _, inv := range invites {
		email := ""
		if inv.Email.Valid {
			email = inv.Email.String
		}
		state := "pending"
		if !inv.Email.Valid {
			state = "active"
		}
		switch {
		case inv.Email.Valid && inv.UsedAt.Valid:
			state = "used"
		case !inv.ExpiresAt.After(now):
			state = "expired"
		}
		rows = append(rows, adminInviteRow{
			Token:        inv.Token,
			TokenPreview: tokenPreview(inv.Token),
			Email:        email,
			Status:       state,
			Signups:      inv.Signups,
			SignupEmails: inv.SignupEmails,
			Expires:      timeStr(inv.ExpiresAt),
			Created:      timeStr(inv.CreatedAt),
		})
	}
	return s.render(c, status, "admin_invites.html", adminInvitesView{
		Chrome: s.pageChrome(c, "invites"), Error: errMsg, NewLink: newLink, Invites: rows,
		FormEmail: formEmail, FormDays: formDays,
	})
}

func (s *Server) postAdminInvites(c echo.Context) error {
	me, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}

	formEmail := strings.TrimSpace(c.FormValue("email"))
	formDays := strings.TrimSpace(c.FormValue("expires_in_days"))

	days := defaultInviteDays
	if formDays != "" {
		n, err := strconv.Atoi(formDays)
		if err != nil || n <= 0 || n > maxInviteDays {
			return s.renderAdminInvites(c, http.StatusBadRequest, "expires_in_days must be between 1 and 365", "", formEmail, formDays)
		}
		days = n
	}

	var email sql.NullString
	if v := store.NormalizeEmail(formEmail); v != "" {
		email = sql.NullString{String: v, Valid: true}
	}

	// token goes in the link; invites.token holds only its digest.
	token := ids.NewToken()
	expires := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	if _, err := s.q.CreateInvite(c.Request().Context(), store.CreateInviteParams{
		Token:     ids.HashToken(token),
		Email:     email,
		CreatedBy: me.ID,
		ExpiresAt: expires,
	}); err != nil {
		return err
	}

	link := s.absLink("/signup", "invite", token)
	// success: reset the form to its defaults; the new link shows in .secret
	return s.renderAdminInvites(c, http.StatusOK, "", link, "", strconv.Itoa(defaultInviteDays))
}

// postAdminInviteDelete does not hash :token — it comes from the invites
// listing and is already the stored digest.
func (s *Server) postAdminInviteDelete(c echo.Context) error {
	if err := s.q.DeleteInvite(c.Request().Context(), c.Param("token")); err != nil {
		return err
	}
	s.setFlash(c, "Invite deleted.")
	return c.Redirect(http.StatusFound, "/admin/invites")
}

// absLink builds a link to path carrying a single query parameter, prefixed
// with the configured BaseURL when one is set. Used for the one-time invite and
// reset links an admin copies out of the UI and shares out-of-band.
func (s *Server) absLink(path, param, token string) string {
	link := path + "?" + param + "=" + url.QueryEscape(token)
	if s.cfg.BaseURL != "" {
		link = strings.TrimRight(s.cfg.BaseURL, "/") + link
	}
	return link
}

// tokenPreview shortens a stored invite digest so an operator can tell rows
// apart. It is not a preview of the invite link.
func tokenPreview(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "…"
}
