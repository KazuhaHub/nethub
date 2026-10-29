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
	"path/filepath"
	"syscall"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/setup"
)

const relayTokenUsage = `Usage: nethub relay-token <rotate|resume|inspect> [options]

  rotate   Replace the shared token and restart only authz/frps
  resume   Continue the retained operation with its original input
  inspect  Read retained operation metadata; omit the ID to list operations

Rotate requires Linux root, an existing confirmed deployment, an enrolled
nonrevoked device and a separate successor backup path. It interrupts relay
connections; refresh online devices with their existing Rotate credentials
action and retain independent local management throughout the operation.
`

func runRelayToken(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, relayTokenUsage)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, relayTokenUsage)
		return 0
	}
	if args[0] != "rotate" && args[0] != "resume" && args[0] != "inspect" {
		fmt.Fprint(stderr, relayTokenUsage)
		return 2
	}
	o := setup.RelayTokenCommandOptions{Action: args[0]}
	flags := flag.NewFlagSet("relay-token "+o.Action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&o.Directory, "directory", "", "Explicit protected deployment directory")
	project := ""
	if o.Action == "rotate" {
		project = "nethub"
	}
	flags.StringVar(&o.Project, "project-name", project, "Existing Compose project; rotate only")
	flags.StringVar(&o.ComposeFile, "compose-file", "", "Protected existing Compose override; rotate only")
	flags.StringVar(&o.SuccessorBackup, "successor-backup", "", "Independent current-key successor backup; rotate only")
	flags.StringVar(&o.OperationID, "operation-id", "", "Original operation UUID; required for resume")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	invalid := flags.NArg() != 0 || o.Directory == "" || o.OperationID != "" && !protocol.ValidRotationOperationID(o.OperationID)
	if o.Action == "rotate" {
		invalid = invalid || o.Project == "" || o.SuccessorBackup == ""
	} else {
		invalid = invalid || o.Project != "" || o.ComposeFile != "" || o.SuccessorBackup != "" || o.Action == "resume" && o.OperationID == ""
	}
	if invalid {
		fmt.Fprintln(stderr, "Supply an explicit directory and the action's required options; resume uses only its retained UUID")
		return 2
	}
	for _, field := range []*string{&o.Directory, &o.ComposeFile, &o.SuccessorBackup} {
		if *field != "" {
			absolute, err := filepath.Abs(*field)
			if err != nil {
				fmt.Fprintln(stderr, "Deployment or backup path is unavailable")
				return 2
			}
			*field = absolute
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := setup.RunRelayTokenCommand(ctx, o)
	if result.OperationID != "" || o.Action == "inspect" && err == nil {
		if json.NewEncoder(stdout).Encode(result) != nil {
			return 1
		}
	}
	if errors.Is(err, hostlease.ErrBusy) {
		fmt.Fprintln(stderr, "Another protected relay operation holds the shared lease")
		return 3
	}
	if err != nil {
		fmt.Fprintln(stderr, "Shared relay token operation is unconfirmed; inspect retained state before retrying the same operation")
		return 1
	}
	return 0
}
