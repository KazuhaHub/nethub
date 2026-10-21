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
	"runtime"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/http01"
)

func runHTTP01Cleanup(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("certificates cleanup-http01", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := flags.String("config-file", "/etc/nethub/http01.json", "Existing protected HTTP-01 publisher policy file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "HTTP-01 cleanup requires the Linux root host")
		return 1
	}
	publisher, err := http01.OpenExistingFile(*config)
	if errors.Is(err, http01.ErrBusy) {
		fmt.Fprintln(stdout, "HTTP-01 publisher namespace busy; skipped")
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "HTTP-01 cleanup policy or existing namespace unavailable")
		return 1
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(interrupted, 30*time.Second)
	defer cancel()
	var total http01.SweepResult
	for {
		result, err := publisher.SweepExpired(ctx)
		total.Scanned += result.Scanned
		total.Retired += result.Retired
		total.Busy += result.Busy
		total.Errors += result.Errors
		total.CycleComplete = result.CycleComplete
		if errors.Is(err, http01.ErrBusy) {
			fmt.Fprintln(stdout, "HTTP-01 cleanup already running; skipped")
			return 0
		}
		if err != nil || result.CycleComplete {
			if json.NewEncoder(stdout).Encode(total) != nil {
				return 1
			}
			if err != nil {
				fmt.Fprintln(stderr, "HTTP-01 cleanup incomplete; inspect protected publisher state")
				return 1
			}
			return 0
		}
	}
}
