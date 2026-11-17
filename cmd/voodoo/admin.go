package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/0xD34DC0D3/voodoo/internal/auth/config"
	"github.com/0xD34DC0D3/voodoo/internal/auth/password"
	"github.com/0xD34DC0D3/voodoo/internal/auth/store"
	"github.com/0xD34DC0D3/voodoo/internal/ids"
)

// Bootstrap sequence for a fresh deployment (no users yet):
//
//  1. voodoo migrate up
//  2. voodoo admin create-user --email <e> --admin
//     prompts for the password (never a flag: argv shows up in ps and shell
//     history) and prints the new user's ID on stdout.
//  3. Log in as that user and create invites at /admin/invites. Invite tokens
//     are stored hashed, so the only usable link is the one shown when the
//     invite is created.
func runAdmin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: voodoo admin <create-user|promote|demote|list>")
	}
	switch args[0] {
	case "create-user":
		return runAdminCreateUser(args[1:])
	case "promote":
		return runAdminSetAdmin(args[1:], true)
	case "demote":
		return runAdminSetAdmin(args[1:], false)
	case "list":
		return runAdminList(args[1:])
	default:
		return fmt.Errorf("admin %q: not yet implemented", args[0])
	}
}

func runAdminCreateUser(args []string) error {
	fs := flag.NewFlagSet("admin create-user", flag.ContinueOnError)
	email := fs.String("email", "", "user email")
	admin := fs.Bool("admin", false, "mark user as admin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *email == "" {
		v, err := promptLine("email: ")
		if err != nil {
			return err
		}
		*email = v
	}
	*email = store.NormalizeEmail(*email)
	if *email == "" {
		return fmt.Errorf("email is required")
	}

	pw, err := promptPassword("password: ")
	if err != nil {
		return err
	}
	if err := password.CheckNew(pw); err != nil {
		return err
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
	q := store.New(db)

	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	u, err := q.CreateUser(context.Background(), store.CreateUserParams{
		ID:           ids.NewID(),
		Email:        *email,
		PasswordHash: hash,
		IsAdmin:      *admin,
	})
	if err != nil {
		return err
	}
	fmt.Println(u.ID)
	return nil
}

func runAdminSetAdmin(args []string, isAdmin bool) error {
	verb := "promote"
	if !isAdmin {
		verb = "demote"
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: voodoo admin %s <email>", verb)
	}
	email := store.NormalizeEmail(args[0])
	if email == "" {
		return fmt.Errorf("email is required")
	}

	q, closeFn, err := openAdminQueries()
	if err != nil {
		return err
	}
	defer closeFn()

	ctx := context.Background()
	u, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("user %q not found", email)
	}
	if u.IsAdmin == isAdmin {
		fmt.Fprintf(os.Stderr, "%s is already %s\n", email, adminLabel(isAdmin))
		return nil
	}
	if err := q.SetUserAdmin(ctx, store.SetUserAdminParams{IsAdmin: isAdmin, ID: u.ID}); err != nil {
		return err
	}
	fmt.Printf("%s %s -> %s\n", verb, email, adminLabel(isAdmin))
	return nil
}

func runAdminList(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: voodoo admin list")
	}
	q, closeFn, err := openAdminQueries()
	if err != nil {
		return err
	}
	defer closeFn()

	users, err := q.ListUsers(context.Background())
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "EMAIL\tADMIN\tSTATUS\tCREATED")
	for _, u := range users {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			u.Email,
			adminLabel(u.IsAdmin),
			statusLabel(u.DisabledAt),
			u.CreatedAt.UTC().Format(time.RFC3339),
		)
	}
	return w.Flush()
}

func adminLabel(b bool) string {
	if b {
		return "admin"
	}
	return "user"
}

func statusLabel(t sql.NullTime) string {
	if t.Valid {
		return "disabled"
	}
	return "active"
}

// openAdminQueries opens the configured DB and returns a Queries handle plus a
// closer. Centralized so each admin subcommand has the same boilerplate.
func openAdminQueries() (*store.Queries, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, nil, err
	}
	return store.New(db), func() { db.Close() }, nil
}

func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
