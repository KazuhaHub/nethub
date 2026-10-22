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
	if len(args) == 0 || args[0] != "prepare" && args[0] != "inspect" && args[0] != "backup" && args[0] != "verify-backup" {
		fmt.Fprintln(stderr, "Usage: nethub certificates relay-authority prepare|inspect|backup|verify-backup --directory PATH --candidate-directory PATH [--expected-root SHA256|--backup-directory PATH]")
		return 2
	}
	o := setup.RelayAuthorityOptions{Action: args[0]}
	flags := flag.NewFlagSet("certificates relay-authority "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&o.Directory, "directory", ".", "Confirmed deployment directory")
	flags.StringVar(&o.CandidateDirectory, "candidate-directory", "", "Protected offline candidate outside deployment/runtime/backup")
	flags.StringVar(&o.BackupDirectory, "backup-directory", "", "Independent offline backup directory")
	flags.StringVar(&o.ExpectedRoot, "expected-root", "", "Exact current authority root SHA256 for explicit preparation")
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
