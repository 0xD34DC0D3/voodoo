package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"

	"github.com/0xD34DC0D3/voodoo/internal/auth/config"
	"github.com/0xD34DC0D3/voodoo/internal/auth/oauth"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/web"
)

type Server struct {
	cfg *config.Config
	db  *sql.DB
	q   *store.Queries
	e   *echo.Echo

	// registerLimiter caps dynamic client registration, the only unauthenticated
	// endpoint that writes rows.
	registerLimiter echo.MiddlewareFunc
	// credLimiter caps password form posts (login, signup, reset) per address.
	credLimiter echo.MiddlewareFunc
	// tokenLimiter caps /token per address, separately from credLimiter.
	tokenLimiter echo.MiddlewareFunc

	// hashSlot is the one-slot semaphore around argon2; see hashslot.go.
	hashSlot chan struct{}
	hashWait time.Duration
}

func New(cfg *config.Config, db *sql.DB) *Server {
	e := echo.New()
	e.HideBanner = true
	e.Use(requestLogger)
	e.Use(securityHeaders)
	e.Use(middleware.Recover())
	// Every route takes at most a small form or JSON body; nothing uploads.
	e.Use(middleware.BodyLimit("64K"))

	// Bound how long a slow or idle client can hold a connection. Write covers
	// the slowest handler (an argon2 hash queued behind others) with room to
	// spare; Idle must stay above the reverse proxy's upstream keepalive.
	e.Server.ReadHeaderTimeout = 5 * time.Second
	e.Server.ReadTimeout = 10 * time.Second
	e.Server.WriteTimeout = 30 * time.Second
	e.Server.IdleTimeout = 60 * time.Second

	// Echo's default RealIP() trusts X-Forwarded-For from anyone, which makes any
	// per-IP decision — the rate limits, the address recorded on a session —
	// something the caller can choose. This extractor trusts the header only from
	// a loopback peer, which is exactly the proxy-on-the-same-host deployment
	// voodoo runs in, and falls back to the socket address otherwise.
	e.IPExtractor = echo.ExtractIPFromXFFHeader(
		echo.TrustLinkLocal(false),
		echo.TrustPrivateNet(false),
	)

	s := &Server{
		cfg: cfg, db: db, q: store.New(db), e: e,
		registerLimiter: registerRateLimiter(),
		credLimiter:     credentialRateLimiter(),
		tokenLimiter:    tokenRateLimiter(),
		hashSlot:        make(chan struct{}, 1),
		hashWait:        hashWait,
	}
	// After construction: the cross-origin check reads cfg for the logout carve-out.
	e.Use(s.crossOriginMiddleware())
	s.routes()
	return s
}

// registerRateLimiter caps dynamic client registration per address (IPv6 per /64,
// like the other limiters; see limiterKey). It exists for that
// one endpoint: /register is unauthenticated and writes a row, so without a cap
// anyone who can reach voodoo can fill the clients table. Everything else that
// writes is behind a session or an API key.
//
// A client registers once, ever. Five in a burst then one a minute is generous for
// that and useless for filling a table.
func registerRateLimiter() echo.MiddlewareFunc {
	return ipRateLimiter(time.Minute, 5, func(c echo.Context) error {
		return oauthError(c, http.StatusTooManyRequests, oauth.ErrCodeInvalidRequest,
			"too many requests from this address; slow down")
	})
}

// credentialRateLimiter caps password form posts per client address. The three
// routes share one bucket per address: each one runs argon2 and takes a guess at
// a secret, so together they are one budget. Ten in a burst then one every six
// seconds is plenty for a person mistyping and slow for a guesser.
func credentialRateLimiter() echo.MiddlewareFunc {
	return ipRateLimiter(6*time.Second, 10, func(c echo.Context) error {
		return c.String(http.StatusTooManyRequests, "too many attempts from this address; try again shortly")
	})
}

// tokenRateLimiter caps /token per client address, in its own bucket so OAuth
// clients and people logging in cannot starve each other. A client redeems a code
// once and refreshes about hourly; thirty in a burst then one every two seconds
// leaves room for many clients behind one NAT and none for guessing codes.
func tokenRateLimiter() echo.MiddlewareFunc {
	return ipRateLimiter(2*time.Second, 30, func(c echo.Context) error {
		return oauthError(c, http.StatusTooManyRequests, oauth.ErrCodeInvalidRequest,
			"too many requests from this address; slow down")
	})
}

// ipRateLimiter is a token bucket per client address (see limiterKey): burst
// requests, then one per every. Each call is a separate set of buckets.
func ipRateLimiter(every time.Duration, burst int, deny func(echo.Context) error) echo.MiddlewareFunc {
	retry := strconv.Itoa(int(every.Seconds() + 0.5))
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:  rate.Every(every),
				Burst: burst,
				// Forgetting an address idle for ten minutes keeps the map bounded;
				// every bucket here refills well within that.
				ExpiresIn: 10 * time.Minute,
			}),
		IdentifierExtractor: func(c echo.Context) (string, error) {
			return limiterKey(c.RealIP()), nil
		},
		DenyHandler: func(c echo.Context, _ string, _ error) error {
			c.Response().Header().Set("Retry-After", retry)
			return deny(c)
		},
	})
}

// limiterKey is the rate-limit bucket for ip. An IPv6 host typically holds a
// whole /64, so keying on the full address would hand it 2^64 buckets.
func limiterKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// Handler exposes the underlying http.Handler for tests.
func (s *Server) Handler() http.Handler { return s.e }

// inTx runs fn against a transaction, committing if it returns nil and rolling back
// otherwise. Every multi-statement mutation goes through here: a forgotten Commit is
// a silent no-op, and "the revocation appeared to succeed" is not a failure mode
// worth leaving to a hand-written boilerplate block per call site.
func (s *Server) inTx(ctx context.Context, fn func(*store.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) routes() {
	s.e.GET("/healthz", s.healthz)
	s.e.StaticFS("/static", web.Static)

	// "/" is the logged-in landing page; unauthenticated visitors are
	// redirected to /login by the middleware rather than seeing a 404.
	s.e.GET("/", s.getHome, s.requireUser(authModeHTML))
	s.e.POST("/settings/timezone", s.postSettingsTimezone, s.requireUser(authModeHTML))

	s.e.GET("/login", s.getLogin)
	s.e.POST("/login", s.postLogin, s.credLimiter)
	s.e.POST("/logout", s.postLogout)
	s.e.GET("/signup", s.getSignup)
	s.e.POST("/signup", s.postSignup, s.credLimiter)
	s.e.GET("/reset", s.getReset)
	s.e.POST("/reset", s.postReset, s.credLimiter)

	// The only route the parent-domain cookie reaches (besides /logout).
	s.e.GET("/me", s.getMe, s.requireIdentity(authModeJSON))

	s.e.GET("/keys", s.getKeys, s.requireUser(authModeHTML))
	// Minting a key takes a browser session: a leaked key must not be able to
	// mint replacements that outlive its own revocation.
	s.e.POST("/keys", s.postKeys, s.requireSession(authModeHTML), noStoreMiddleware)
	s.e.POST("/keys/:id/delete", s.postKeysDelete, s.requireUser(authModeHTML))

	s.oauthRoutes()

	s.e.GET("/connections", s.getConnections, s.requireUser(authModeHTML))
	s.e.POST("/connections/revoke", s.postConnectionsRevoke, s.requireUser(authModeHTML))

	// Routes that render a one-time secret (API key, reset link, invite link)
	// carry noStoreMiddleware so the page stays out of caches.
	admin := s.e.Group("", s.requireAdmin(authModeHTML), auditAdmin)
	admin.GET("/admin", s.getAdmin)
	admin.GET("/admin/users", s.getAdminUsers)
	// Every action on /admin/users/:id 404s on an unknown id; see requireTargetUser.
	admin.POST("/admin/users/:id/disable", s.postAdminUserDisable, s.requireTargetUser)
	admin.POST("/admin/users/:id/enable", s.postAdminUserEnable, s.requireTargetUser)
	admin.POST("/admin/users/:id/sessions/revoke", s.postAdminUserRevokeSessions, s.requireTargetUser)
	admin.POST("/admin/users/:id/promote", s.postAdminUserPromote, s.requireTargetUser)
	admin.POST("/admin/users/:id/demote", s.postAdminUserDemote, s.requireTargetUser)
	admin.POST("/admin/users/:id/reset", s.postAdminUserReset, s.requireTargetUser, noStoreMiddleware)
	admin.GET("/admin/invites", s.getAdminInvites)
	admin.POST("/admin/invites", s.postAdminInvites, noStoreMiddleware)
	admin.POST("/admin/invites/:token/delete", s.postAdminInviteDelete)
	admin.GET("/admin/clients", s.getAdminClients)
	admin.POST("/admin/clients/:id/delete", s.postAdminClientDelete)
}

// oauthRoutes registers the OAuth 2.1 authorization server surface.
func (s *Server) oauthRoutes() {
	// RFC 8414 discovery. The openid-configuration path serves the same document:
	// clients commonly probe it, and answering with honest OAuth metadata beats a
	// 404 that stalls discovery. Voodoo is not an OpenID Provider — it issues no
	// ID tokens — and the document says so by omission. It is also the only OAuth
	// response here that is safe to cache, so it sits outside the group below.
	s.e.GET("/.well-known/oauth-authorization-server", s.getOAuthMetadata)
	s.e.GET("/.well-known/openid-configuration", s.getOAuthMetadata)

	// Every endpoint below either returns a credential or redirects with one in the
	// Location header, so none of it may be cached. Wired once here rather than
	// remembered per route. (The body limit is global; see New.)
	oauth := s.e.Group("", noStoreMiddleware)

	oauth.POST("/register", s.postRegister, s.registerLimiter)

	// The consent screen is bound to a browser session: approving a client is a
	// decision only a person at a browser should make, and the CSRF token is derived
	// from the session ID.
	oauth.GET("/authorize", s.getAuthorize, s.requireSession(authModeHTML))
	oauth.POST("/authorize", s.postAuthorize, s.requireSession(authModeHTML))

	oauth.POST("/token", s.postToken, s.tokenLimiter)
	// Introspection is for resource servers, which authenticate with an API key.
	oauth.POST("/introspect", s.postIntrospect, s.requireAPIKey(authModeJSON))
	oauth.POST("/revoke", s.postRevoke)
}

func (s *Server) healthz(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		c.Set(ctxLogErrKey, err)
		return c.String(http.StatusInternalServerError, "db unavailable")
	}
	return c.String(http.StatusOK, "ok")
}

// sweepInterval is how often expired OAuth codes and tokens are deleted. Nothing
// depends on the sweep for correctness — every lookup checks expires_at itself —
// so this only keeps the tables from growing without bound.
const sweepInterval = time.Hour

// sweepExpired deletes rows that can no longer authorize anything.
func (s *Server) sweepExpired(ctx context.Context) {
	now := time.Now().UTC()
	if err := s.q.DeleteExpiredOAuthCodes(ctx, now); err != nil {
		slog.Error("sweep oauth codes", "err", err)
	}
	if err := s.q.DeleteExpiredOAuthTokens(ctx, now); err != nil {
		slog.Error("sweep oauth tokens", "err", err)
	}
}

// Run starts the HTTP server and blocks until ctx is cancelled, then performs
// a graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.cfg.BindHost, strconv.Itoa(s.cfg.Port))
	// Compute the timing-equalizer hash before taking traffic, so its one argon2
	// run happens outside the request path and the hash slot.
	getDummyHash()

	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		s.sweepExpired(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepExpired(ctx)
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.e.Start(addr)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.e.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
