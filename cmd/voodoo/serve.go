package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/0xD34DC0D3/voodoo/internal/auth/config"
	"github.com/0xD34DC0D3/voodoo/internal/auth/server"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
)

func runServe(_ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.CheckServe(); err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("VOODOO_LOG_LEVEL: %w", err)
	}
	slog.SetLogLoggerLevel(level)

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, db)
	return srv.Run(ctx)
}
