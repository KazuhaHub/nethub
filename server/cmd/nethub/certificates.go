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

	"github.com/KazuhaHub/nethub/server/internal/relaymaint"
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func runCertificates(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "cleanup-http01" {
		return runHTTP01Cleanup(args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] != "maintain-relay" {
		fmt.Fprintln(stderr, "Usage: nethub certificates maintain-relay --directory PATH --project-name NAME | cleanup-http01 --config-file PATH")
		return 2
	}
	flags := flag.NewFlagSet("certificates maintain-relay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", ".", "Protected initialized deployment directory")
	project := flags.String("project-name", "nethub", "Existing local Compose project")
	override := flags.String("compose-file", "", "Additional protected root-owned Compose override, if deployment uses one")
	retry := flags.Bool("retry", false, "Explicitly retry a pending or exhausted generation without reissuing it")
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
	ctx, cancel := context.WithTimeout(interrupted, 2*time.Minute)
	defer cancel()
	state, err := setup.MaintainRelay(ctx, setup.MaintenanceOptions{Directory: *directory, Project: *project, ComposeFile: *override, Retry: *retry})
	if errors.Is(err, relaymaint.ErrBusy) {
		fmt.Fprintln(stdout, "Relay maintenance already running; skipped")
		return 0
	}
	if state.Version == 1 {
		if json.NewEncoder(stdout).Encode(state) != nil {
			return 1
		}
	}
	if err != nil && state.ErrorCode != "service_stopped" {
		fmt.Fprintln(stderr, "Relay maintenance failed; inspect protected state and the fixed status code")
		return 1
	}
	return 0
}
