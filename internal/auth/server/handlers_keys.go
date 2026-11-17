package server

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/apikey"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

const (
	maxKeyNameLen = 100
	maxKeyDays    = 3650
)

type keyRow struct {
	ID       string
	Name     string
	Prefix   string
	Created  string
	LastUsed string
	Expires  string
}

type keysView struct {
	web.Chrome
	Error string
	Keys  []keyRow
	// submitted values, re-populated into the create form after a validation
	// error so the user doesn't have to retype
	Name string
	Days string
}

type newKeyView struct {
	web.Chrome
	Name string
	Raw  string
}

func (s *Server) getKeys(c echo.Context) error {
	return s.renderKeysList(c, http.StatusOK, "", "", "")
}

func (s *Server) postKeys(c echo.Context) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}

	name := strings.TrimSpace(c.FormValue("name"))
	days := strings.TrimSpace(c.FormValue("expires_in_days"))
	if name == "" {
		return s.renderKeysList(c, http.StatusBadRequest, "name is required", name, days)
	}
	if len(name) > maxKeyNameLen {
		return s.renderKeysList(c, http.StatusBadRequest, "name is too long", name, days)
	}

	var expiresAt sql.NullTime
	if days != "" {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > maxKeyDays {
			return s.renderKeysList(c, http.StatusBadRequest, "expires_in_days must be between 1 and 3650", name, days)
		}
		expiresAt = sql.NullTime{Time: time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour), Valid: true}
	}

	raw, hash, prefix, err := apikey.Generate()
	if err != nil {
		return err
	}
	_, err = s.q.CreateApiKey(c.Request().Context(), store.CreateApiKeyParams{
		ID:        ids.NewID(),
		UserID:    u.ID,
		Hash:      hash,
		Prefix:    prefix,
		Name:      name,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	// The one-time secret reveal is a narrow page, unlike the /keys table it
	// shares a route with — wideFor keys off the path and can't tell them apart.
	ch := s.pageChrome(c, "new API key")
	ch.Wide = false
	return s.render(c, http.StatusOK, "keys_new.html", newKeyView{
		Chrome: ch, Name: name, Raw: raw,
	})
}

func (s *Server) postKeysDelete(c echo.Context) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	if err := s.q.DeleteApiKey(c.Request().Context(), store.DeleteApiKeyParams{
		ID:     c.Param("id"),
		UserID: u.ID,
	}); err != nil {
		return err
	}
	s.setFlash(c, "API key deleted.")
	return c.Redirect(http.StatusFound, "/keys")
}

func (s *Server) renderKeysList(c echo.Context, status int, errMsg, name, days string) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	keys, err := s.q.ListApiKeysByUser(c.Request().Context(), u.ID)
	if err != nil {
		return err
	}
	rows := make([]keyRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, keyRow{
			ID:       k.ID,
			Name:     k.Name,
			Prefix:   k.Prefix,
			Created:  timeStr(k.CreatedAt),
			LastUsed: nullTimeStr(k.LastUsedAt),
			Expires:  nullTimeStr(k.ExpiresAt),
		})
	}
	return s.render(c, status, "keys.html", keysView{
		Chrome: s.pageChrome(c, "API keys"), Error: errMsg, Keys: rows,
		Name: name, Days: days,
	})
}

// timeStr and nullTimeStr are how all view rows display timestamps (UTC).
func timeStr(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04")
}

func nullTimeStr(t sql.NullTime) string {
	if !t.Valid {
		return "never"
	}
	return timeStr(t.Time)
}
