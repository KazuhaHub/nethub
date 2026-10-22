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

func runRelayTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "current" && args[0] != "publish" {
		fmt.Fprintln(stderr, "Usage: nethub certificates relay-trust current|publish --directory PATH --project-name NAME [--bundle-file PATH --initialize|--expected-generation ID]")
		return 2
	}
	flags := flag.NewFlagSet("certificates relay-trust "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	o := setup.RelayTrustOptions{Action: args[0]}
	flags.StringVar(&o.Directory, "directory", ".", "Confirmed deployment directory")
	flags.StringVar(&o.Project, "project-name", "nethub", "Existing local Compose project")
	flags.StringVar(&o.ComposeFile, "compose-file", "", "Additional protected Compose override")
	flags.StringVar(&o.BundleFile, "bundle-file", "", "Protected root-owned public CA bundle file")
	flags.StringVar(&o.ExpectedGeneration, "expected-generation", "", "Current generation ID for compare-and-swap")
	flags.BoolVar(&o.Initialize, "initialize", false, "Explicit first publication or exact initial retry")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || o.Action == "current" && (o.BundleFile != "" || o.ExpectedGeneration != "" || o.Initialize) ||
		o.Action == "publish" && (o.BundleFile == "" || o.Initialize == (o.ExpectedGeneration != "")) {
		fmt.Fprintln(stderr, "current accepts no publication flags; publish requires a bundle and exactly one of --initialize or --expected-generation")
		return 2
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 90*time.Second)
	defer cancel()
	value, err := setup.RunRelayTrust(ctx, o)
	if err != nil {
		fmt.Fprintln(stderr, "Relay trust operation refused; inspect the protected authority, bundle and current generation")
		return 1
	}
	if json.NewEncoder(stdout).Encode(value) != nil {
		return 1
	}
	return 0
}
