package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

// Connected apps. Dynamic client registration means the operator never approves a
// client in advance, so this page is where approvals become visible after the fact
// — and, more to the point, revocable.

type connectionRow struct {
	ClientID   string
	ClientName string
	ClientURI  string
	Resource   string
	Scopes     []string
	Granted    string
	LastUsed   string
	Expires    string
}

type connectionsView struct {
	web.Chrome
	Connections []connectionRow
}

type adminClientRow struct {
	ID           string
	Name         string
	ClientURI    string
	RedirectURIs []string
	Created      string
	// FirstApprovedBy is empty for a client that registered and was never approved
	// — the row that granted nothing to anybody.
	FirstApprovedBy string
}

type adminClientsView struct {
	web.Chrome
	Clients []adminClientRow
}

func (s *Server) getConnections(c echo.Context) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	rows, err := s.q.ListOAuthGrantsByUser(c.Request().Context(), store.ListOAuthGrantsByUserParams{
		UserID:    u.ID,
		ExpiresAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return s.render(c, http.StatusOK, "connections.html", connectionsView{
		Chrome:      s.pageChrome(c, "connected apps"),
		Connections: groupConnections(rows),
	})
}

// groupConnections collapses a grant's live tokens into one display row.
//
// The key is client *and* resource, not client alone: the same client may hold
// separate tokens for two different apps, and those are two grants a user must be
// able to revoke independently.
func groupConnections(rows []store.ListOAuthGrantsByUserRow) []connectionRow {
	type key struct{ clientID, resource string }
	// The timestamps accumulate as time.Time so the comparisons never run on display
	// strings.
	type grant struct {
		row      connectionRow
		expires  time.Time
		lastUsed sql.NullTime
	}

	order := make([]key, 0, len(rows))
	seen := make(map[key]*grant, len(rows))

	for _, r := range rows {
		k := key{r.ClientID, r.Resource}
		g, ok := seen[k]
		if !ok {
			g = &grant{row: connectionRow{
				ClientID:   r.ClientID,
				ClientName: r.ClientName,
				ClientURI:  r.ClientUri.String,
				Resource:   r.Resource,
				Scopes:     oauth.ScopeDescriptions(r.Scope),
				Granted:    timeStr(r.GrantedAt),
			}}
			seen[k] = g
			order = append(order, k)
		}
		// A grant's access and refresh tokens expire at different times; the one that
		// matters to the user is whichever keeps the app working longest.
		g.expires = latest(g.expires, r.ExpiresAt)
		if r.LastUsedAt.Valid && (!g.lastUsed.Valid || r.LastUsedAt.Time.After(g.lastUsed.Time)) {
			g.lastUsed = r.LastUsedAt
		}
	}

	out := make([]connectionRow, 0, len(order))
	for _, k := range order {
		g := seen[k]
		g.row.Expires = timeStr(g.expires)
		g.row.LastUsed = nullTimeStr(g.lastUsed)
		out = append(out, g.row)
	}
	return out
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// postConnectionsRevoke deletes every token for one grant. Deletion rather than a
// revoked_at flag, matching how session revocation already works: the user asked for
// this one gone, and there is no rotation chain left to detect reuse in.
func (s *Server) postConnectionsRevoke(c echo.Context) error {
	u, ok := UserFromContext(c)
	if !ok {
		return c.NoContent(http.StatusUnauthorized)
	}
	ctx := c.Request().Context()
	clientID, resource := c.FormValue("client_id"), c.FormValue("resource")

	if err := s.inTx(ctx, func(q *store.Queries) error {
		if err := q.DeleteOAuthTokensByUserClientResource(ctx,
			store.DeleteOAuthTokensByUserClientResourceParams{
				UserID: u.ID, ClientID: clientID, Resource: resource,
			}); err != nil {
			return err
		}
		// An authorization code issued moments ago is still redeemable for a fresh
		// full-lifetime grant, so deleting only tokens would make this revocation
		// reversible by whoever holds that code.
		return q.DeleteOAuthCodesByUserClientResource(ctx,
			store.DeleteOAuthCodesByUserClientResourceParams{
				UserID: u.ID, ClientID: clientID, Resource: resource,
			})
	}); err != nil {
		return err
	}

	s.setFlash(c, "Access revoked.")
	return c.Redirect(http.StatusFound, "/connections")
}

// getAdminClients lists every registered client. Because /register is open, this is
// the operator's window onto what has asked for a client_id — the place to notice a
// name nobody recognises.
func (s *Server) getAdminClients(c echo.Context) error {
	clients, err := s.q.ListOAuthClients(c.Request().Context())
	if err != nil {
		return err
	}
	rows := make([]adminClientRow, 0, len(clients))
	for _, cl := range clients {
		rows = append(rows, adminClientRow{
			ID:              cl.ID,
			Name:            cl.Name,
			ClientURI:       cl.ClientUri.String,
			RedirectURIs:    oauth.DecodeRedirectURIs(cl.RedirectUris),
			Created:         timeStr(cl.CreatedAt),
			FirstApprovedBy: cl.FirstApprovedByEmail.String,
		})
	}
	return s.render(c, http.StatusOK, "admin_clients.html", adminClientsView{
		Chrome: s.pageChrome(c, "clients"), Clients: rows,
	})
}

// postAdminClientDelete removes a client. The oauth_codes and oauth_tokens rows
// referencing it cascade away with it, so this revokes every outstanding grant held
// by that client, for every user.
func (s *Server) postAdminClientDelete(c echo.Context) error {
	n, err := s.q.DeleteOAuthClient(c.Request().Context(), c.Param("id"))
	if err != nil {
		return err
	}
	// Claiming tokens were revoked when nothing matched would be the worst kind of
	// wrong: an admin containing an incident deserves to know the button missed.
	if n == 0 {
		s.setFlash(c, "Client not found. Nothing was deleted.")
	} else {
		s.setFlash(c, "Client deleted. Its tokens are revoked for everyone.")
	}
	return c.Redirect(http.StatusFound, "/admin/clients")
}
