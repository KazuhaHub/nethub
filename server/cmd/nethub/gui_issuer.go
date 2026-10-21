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

func runGUIIssuer(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("certificates issue-gui", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "/srv/nethub-deployment", "Existing protected deployment directory")
	project := flags.String("project-name", "nethub", "Existing local Compose project")
	policy := flags.String("config-file", "/etc/nethub/gui-issuer.json", "Protected issuer account/trust/cleanup policy")
	override := flags.String("compose-file", "", "Additional protected Compose override, if configured")
	if err := flags.Parse(args); err != nil {
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
	ctx, cancel := context.WithTimeout(interrupted, 3*time.Minute)
	defer cancel()
	result, err := setup.RunGUIIssuer(ctx, setup.GUIIssuerOptions{Directory: *directory, Project: *project, ConfigFile: *policy, ComposeFile: *override})
	if errors.Is(err, setup.ErrGUIIssuerBusy) {
		fmt.Fprintln(stdout, "GUI issuer already running or namespace busy; skipped")
		return 0
	}
	if result.State != "" && json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "GUI certificate issuance unavailable; verify protected deployment, account, cleanup and database readiness")
		return 1
	}
	if result.State == "terminal" {
		return 1
	}
	return 0
}
