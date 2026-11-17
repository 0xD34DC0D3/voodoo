package main

import (
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/0xD34DC0D3/voodoo/internal/auth/config"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/migrations"
)

func runMigrate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: voodoo migrate <up|down|status>")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}

	switch args[0] {
	case "up":
		return goose.Up(db, ".")
	case "down":
		return goose.Down(db, ".")
	case "status":
		return goose.Status(db, ".")
	default:
		return fmt.Errorf("unknown migrate command %q (want up|down|status)", args[0])
	}
}
