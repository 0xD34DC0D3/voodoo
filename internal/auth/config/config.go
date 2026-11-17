package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DBPath string
	Port   int

	// BindHost is the interface the HTTP listener attaches to. Defaults to
	// loopback: the reverse proxy is the only intended client, and voodoo
	// terminates no TLS of its own, so nothing should reach it directly. Set
	// VOODOO_BIND to an empty string to listen on all interfaces.
	BindHost string

	BaseURL      string
	CookieDomain string
	CookieSecure bool
	SessionTTL   time.Duration
	LogLevel     string

	// OAuth token lifetimes. The access TTL is short because an access token is
	// a bearer credential a downstream app holds; the refresh TTL is the absolute
	// ceiling on an authorization — rotation issues new refresh tokens but never
	// extends this deadline, so an approval always expires when the user expects
	// it to rather than living forever through use.
	OAuthAccessTTL  time.Duration
	OAuthRefreshTTL time.Duration
}

func Load() (*Config, error) {
	dbPath := os.Getenv("VOODOO_DB_PATH")
	if dbPath == "" {
		return nil, errors.New("VOODOO_DB_PATH is required")
	}

	port, err := envInt("VOODOO_PORT", 8080)
	if err != nil {
		return nil, err
	}
	cookieSecure, err := envBool("VOODOO_COOKIE_SECURE", true)
	if err != nil {
		return nil, err
	}
	sessionDays, err := envInt("VOODOO_SESSION_TTL_DAYS", 30)
	if err != nil {
		return nil, err
	}
	accessMinutes, err := envInt("VOODOO_OAUTH_ACCESS_TTL_MINUTES", 60)
	if err != nil {
		return nil, err
	}
	refreshDays, err := envInt("VOODOO_OAUTH_REFRESH_TTL_DAYS", 30)
	if err != nil {
		return nil, err
	}
	// A non-positive lifetime would mint tokens that are already expired — a
	// confusing way to discover a typo, so refuse to start instead.
	if accessMinutes <= 0 {
		return nil, errors.New("VOODOO_OAUTH_ACCESS_TTL_MINUTES must be positive")
	}
	if refreshDays <= 0 {
		return nil, errors.New("VOODOO_OAUTH_REFRESH_TTL_DAYS must be positive")
	}

	// envOr treats "" as unset, but VOODOO_BIND="" is the explicit "all
	// interfaces" escape hatch, so it is special-cased.
	bindHost := envOr("VOODOO_BIND", "127.0.0.1")
	if v, ok := os.LookupEnv("VOODOO_BIND"); ok && v == "" {
		bindHost = ""
	}

	return &Config{
		DBPath:       dbPath,
		Port:         port,
		BindHost:     bindHost,
		BaseURL:      os.Getenv("VOODOO_BASE_URL"),
		CookieDomain: os.Getenv("VOODOO_COOKIE_DOMAIN"),
		CookieSecure: cookieSecure,
		SessionTTL:   time.Duration(sessionDays) * 24 * time.Hour,
		LogLevel:     envOr("VOODOO_LOG_LEVEL", "info"),

		OAuthAccessTTL:  time.Duration(accessMinutes) * time.Minute,
		OAuthRefreshTTL: time.Duration(refreshDays) * 24 * time.Hour,
	}, nil
}

// CheckServe validates settings only the HTTP server needs. It is separate from
// Load so `migrate` and `admin` keep working with just VOODOO_DB_PATH.
//
// With secure cookies voodoo is running for real, and BaseURL is the issuer and
// the origin of every invite and reset link; without it those fall back to the
// request's Host header, which the caller controls.
//
// A cookie domain means sibling hosts share the session cookie; sending it over
// plain HTTP would expose it to anyone on the path to any of them.
func (c *Config) CheckServe() error {
	if !c.CookieSecure {
		if c.CookieDomain != "" {
			return errors.New("VOODOO_COOKIE_DOMAIN requires VOODOO_COOKIE_SECURE to be on")
		}
		return nil
	}
	u, err := url.Parse(c.BaseURL)
	if c.BaseURL == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("VOODOO_BASE_URL must be an https URL when VOODOO_COOKIE_SECURE is on")
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}
