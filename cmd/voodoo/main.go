package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// Best-effort: vars already set in the environment take precedence.
	_ = godotenv.Load()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "voodoo: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "voodoo:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`voodoo — auth server + admin tools

Usage:
  voodoo serve
  voodoo migrate up | down | status
  voodoo admin create-user [--email E] [--admin]   (prompts for the password)
  voodoo admin promote <email>
  voodoo admin demote <email>
  voodoo admin list`)
}
