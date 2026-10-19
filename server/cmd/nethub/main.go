package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/store"
)

var version = "dev"

const usage = `Usage: nethub <command>

Commands:
  web          Run the console
  authz        Run device and relay authorization
  migrate      Apply database migrations
  init         Prepare deployment configuration and secrets
  doctor       Check deployment readiness
  admin        Manage the initial administrator
  version      Print the build version

The console, migrations, first-admin setup, deployment initialization, scoped
doctor checks, and device enrollment are implemented. Relay hooks remain unfinished.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version does not accept arguments")
			return 2
		}
		fmt.Fprintln(stdout, "nethub", version)
		return 0
	case "migrate":
		flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
		flags.SetOutput(stderr)
		host := flags.String("host", "postgres", "Database hostname")
		port := flags.Uint("port", 5432, "Database port")
		database := flags.String("database", "nethub", "Database name")
		passwordFile := flags.String("password-file", "", "Owner password file")
		tls := flags.String("sslmode", "verify-full", "verify-full, or disable for an isolated local database")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *port == 0 || *port > 65535 || *passwordFile == "" {
			fmt.Fprintln(stderr, "migrate requires a password file and valid database settings")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		db, err := store.OpenRole(ctx, store.DatabaseConfig{Host: *host, Port: uint16(*port), Database: *database, PasswordFile: *passwordFile, SSLMode: *tls}, "nethub_owner")
		if err != nil {
			fmt.Fprintln(stderr, "Migration database connection failed; check settings and the owner password file")
			return 1
		}
		defer db.Close()
		if err := store.Migrate(ctx, db); err != nil {
			fmt.Fprintln(stderr, "Database migration failed; check role permissions and migration state")
			return 1
		}
		fmt.Fprintln(stdout, "Database migrations applied")
		return 0
	case "web":
		return runWeb(args[1:], stdout, stderr)
	case "admin":
		return runAdmin(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "authz":
		return runAuthz(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "Unknown command. Run nethub help for available commands.")
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
