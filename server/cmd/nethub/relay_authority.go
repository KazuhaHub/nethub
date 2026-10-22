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
	"time"

	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func runRelayAuthority(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "binding", "activate", "resume", "abort", "cancel-preparation":
			return runRelayAuthorityCommand(args, stdout, stderr)
		}
	}
	if len(args) == 0 || args[0] != "prepare" && args[0] != "inspect" && args[0] != "backup" && args[0] != "verify-backup" && args[0] != "acknowledge-backup" && args[0] != "verify-custody" {
		fmt.Fprintln(stderr, "Usage: nethub certificates relay-authority prepare|inspect|backup|verify-backup|acknowledge-backup|verify-custody --directory PATH --candidate-directory PATH [--expected-root SHA256|--backup-directory PATH --custody-file PATH --acknowledge PHRASE]\n       nethub certificates relay-authority binding|activate|resume|abort|cancel-preparation --directory PATH [--options-file PATH|--operation-id UUID]")
		return 2
	}
	o := setup.RelayAuthorityOptions{Action: args[0]}
	flags := flag.NewFlagSet("certificates relay-authority "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&o.Directory, "directory", ".", "Confirmed deployment directory")
	flags.StringVar(&o.CandidateDirectory, "candidate-directory", "", "Protected offline candidate outside deployment/runtime/backup")
	flags.StringVar(&o.BackupDirectory, "backup-directory", "", "Independent offline backup directory")
	flags.StringVar(&o.ExpectedRoot, "expected-root", "", "Exact current authority root SHA256 for explicit preparation")
	flags.StringVar(&o.CustodyFile, "custody-file", "", "New protected acknowledgement receipt outside material directories")
	flags.StringVar(&o.Acknowledgement, "acknowledge", "", "Exact independent-backup acknowledgement phrase")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 30*time.Second)
	defer cancel()
	value, err := setup.RunRelayAuthority(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "Offline authority operation refused; inspect the protected deployment, candidate and backup")
		return 1
	}
	if json.NewEncoder(stdout).Encode(value) != nil {
		return 1
	}
	return 0
}

func runRelayAuthorityCommand(args []string, stdout, stderr io.Writer) int {
	o := setup.RelayAuthorityCommandOptions{Action: args[0]}
	flags := flag.NewFlagSet("certificates relay-authority "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&o.Directory, "directory", "", "Explicit protected deployment directory")
	flags.StringVar(&o.Project, "project-name", "nethub", "Existing local Compose project")
	flags.StringVar(&o.ComposeFile, "compose-file", "", "Protected Compose override used by the retained binding")
	flags.StringVar(&o.OptionsFile, "options-file", "", "Private original transition JSON; activate only")
	flags.StringVar(&o.OperationID, "operation-id", "", "Retained operation UUID; resume, abort or cancel-preparation")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	invalid := flags.NArg() != 0 || o.Directory == "" || o.Project == ""
	switch o.Action {
	case "binding":
		invalid = invalid || o.OptionsFile != "" || o.OperationID != ""
	case "activate":
		invalid = invalid || o.OptionsFile == "" || o.OperationID != ""
	default:
		invalid = invalid || o.OptionsFile != "" || o.OperationID == ""
	}
	if invalid {
		fmt.Fprintln(stderr, "Specify a deployment and exactly the original activation file or retained operation ID required by this action")
		return 2
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 5*time.Minute)
	defer cancel()
	value, err := setup.RunRelayAuthorityCommand(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "Authority operation refused; retain the original input and inspect the protected operation, deployment and database decision")
		return 1
	}
	if json.NewEncoder(stdout).Encode(value) != nil {
		return 1
	}
	return 0
}
