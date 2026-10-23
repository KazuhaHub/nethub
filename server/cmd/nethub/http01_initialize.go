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

func runHTTP01Initialize(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("certificates initialize-http01", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "/srv/nethub-deployment", "Protected initialized deployment directory")
	policy := flags.String("config-file", "/etc/nethub/http01.json", "Protected publisher policy")
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
	ctx, cancel := context.WithTimeout(interrupted, 30*time.Second)
	defer cancel()
	if setup.InitializeHTTP01(ctx, *directory, *policy) != nil {
		fmt.Fprintln(stderr, "HTTP-01 initialization refused; verify deployment backup, protected policy and namespace state")
		return 1
	}
	if json.NewEncoder(stdout).Encode(map[string]string{"state": "initialized"}) != nil {
		return 1
	}
	return 0
}
