package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func runGUIAccount(args []string, stdout, stderr io.Writer) int {
	const usage = "Usage: nethub certificates account initialize|backup|verify-backup|restore|terms|lookup|register --directory PATH --config-file PATH"
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stderr, usage)
		return 0
	}
	switch args[0] {
	case "initialize", "backup", "verify-backup", "restore", "terms", "lookup", "register":
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("certificates account "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "/srv/nethub-deployment", "Existing protected deployment directory")
	policy := flags.String("config-file", "/etc/nethub/gui-issuer.json", "Protected issuer policy")
	backup := flags.String("backup-directory", "", "Independent private account snapshot directory")
	consent := flags.String("terms-file", "", "Protected JSON with exact accepted_terms_reference")
	create := flags.Bool("allow-create", false, "Explicitly authorize new registration with the current accepted terms")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := setup.RunGUIAccount(ctx, setup.GUIAccountOptions{Directory: *directory, ConfigFile: *policy, Action: args[0], BackupDirectory: *backup, TermsFile: *consent, AllowCreate: *create})
	if err != nil {
		if errors.Is(err, guiacme.ErrConsent) {
			fmt.Fprintln(stderr, "Registration needs exact current CA terms consent; review terms and update the protected consent file")
		} else {
			fmt.Fprintln(stderr, "Private account operation failed; verify protected policy, backup and existing identity")
		}
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	return 0
}
