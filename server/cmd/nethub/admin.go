package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/store"
	"golang.org/x/term"
)

func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "create" {
		fmt.Fprintln(stderr, "Usage: nethub admin create --email EMAIL --owner-password-file FILE [--password-stdin]")
		return 2
	}
	flags := flag.NewFlagSet("admin create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	host := flags.String("host", "postgres", "Database hostname")
	port := flags.Uint("port", 5432, "Database port")
	database := flags.String("database", "nethub", "Database name")
	tls := flags.String("sslmode", "verify-full", "verify-full, or disable for an isolated local database")
	ownerPassword := flags.String("owner-password-file", "", "Owner-role database password file, mounted only in the bootstrap service")
	email := flags.String("email", "", "Initial administrator email")
	stdin := flags.Bool("password-stdin", false, "Read the administrator password from protected standard input without a prompt")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *port == 0 || *port > 65535 || *ownerPassword == "" {
		fmt.Fprintln(stderr, "Administrator creation requires owner credentials and valid database settings")
		return 2
	}
	canonical, err := auth.NormalizeEmail(*email)
	if err != nil {
		fmt.Fprintln(stderr, "A valid administrator email is required")
		return 2
	}
	password, err := readAdminPassword(os.Stdin, *stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	defer clear(password)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.OpenRole(ctx, store.DatabaseConfig{Host: *host, Port: uint16(*port), Database: *database, PasswordFile: *ownerPassword, SSLMode: *tls}, "nethub_owner")
	if err != nil {
		fmt.Fprintln(stderr, "Administrator database connection failed; check owner credentials and migrations")
		return 1
	}
	defer db.Close()
	if err = store.CreateInitialAdmin(ctx, db, canonical, string(password)); errors.Is(err, store.ErrAlreadyInitialized) {
		fmt.Fprintln(stderr, "Accounts already exist; initial administrator creation is closed")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "Administrator creation failed; verify migrations, owner permissions, and the single-tenant empty-account state")
		return 1
	}
	fmt.Fprintln(stdout, "Initial administrator created; sign in through the configured HTTPS console")
	return 0
}

func readAdminPassword(input *os.File, fromStdin bool, diagnostic io.Writer) ([]byte, error) {
	if fromStdin {
		return readPasswordInput(input)
	}
	if !term.IsTerminal(int(input.Fd())) {
		return nil, errors.New("A terminal is required for hidden password entry; use --password-stdin only with a protected input source")
	}
	fmt.Fprint(diagnostic, "Administrator password (at least 15 characters): ")
	password, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(diagnostic)
	if err != nil {
		clear(password)
		return nil, errors.New("Password entry failed")
	}
	fmt.Fprint(diagnostic, "Confirm administrator password: ")
	confirmation, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(diagnostic)
	defer clear(confirmation)
	if err != nil || subtle.ConstantTimeCompare(password, confirmation) != 1 {
		clear(password)
		return nil, errors.New("Password confirmation did not match")
	}
	if err = validateAdminPassword(password); err != nil {
		clear(password)
		return nil, err
	}
	return password, nil
}

func readPasswordInput(input io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, auth.MaxPasswordBytes+3))
	if err != nil || len(data) > auth.MaxPasswordBytes+2 {
		clear(data)
		return nil, errors.New("Password input is unavailable or too long")
	}
	// Remove only one terminal line ending; spaces belong to the password.
	password := bytes.TrimSuffix(data, []byte("\n"))
	password = bytes.TrimSuffix(password, []byte("\r"))
	if err = validateAdminPassword(password); err != nil {
		clear(data)
		return nil, err
	}
	return password, nil
}

func validateAdminPassword(password []byte) error {
	if auth.ValidateNewPassword(string(password)) != nil {
		return errors.New("Use a password of at least 15 characters and at most 1024 UTF-8 bytes, without embedded line endings or NUL")
	}
	return nil
}
