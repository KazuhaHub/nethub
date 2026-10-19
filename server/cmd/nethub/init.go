package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func runInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "nethub-deployment", "New private deployment directory")
	backup := flags.String("backup-directory", "", "New separate backup directory, preferably on protected external storage")
	source := flags.String("source-directory", ".", "NetHub source checkout containing deploy/Dockerfile")
	console := flags.String("console-host", "", "Console DNS hostname outside the device wildcard")
	device := flags.String("device-domain", "", "Device DNS base without wildcard")
	subnet := flags.String("network-subnet", "172.30.87.0/24", "Unused private IPv4 /24 for Caddy and the web network")
	expected := flags.String("expected-address", "", "Expected public relay address for DNS preflight")
	skipDNS := flags.Bool("offline", false, "Prepare an offline test bundle; DNS and public readiness remain unverified")
	resume := flags.Bool("resume", false, "Resume only an existing unconfirmed bundle without regenerating secrets")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "init does not accept positional arguments")
		return 2
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run init as root on the Linux Docker host to set private service file ownership")
		return 2
	}
	reader := bufio.NewReader(os.Stdin)
	prompt := func(label string, target *string) bool {
		if *target != "" {
			return true
		}
		fmt.Fprint(stderr, label+": ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		*target = strings.TrimSpace(line)
		return *target != ""
	}
	var previous setup.Manifest
	if *resume {
		loaded, err := setup.Load(*directory)
		if err != nil || loaded.ConfirmedAt != nil {
			fmt.Fprintln(stderr, "Resume requires an intact, unconfirmed deployment bundle")
			return 1
		}
		previous = loaded
		if *console != "" && *console != previous.Config.ConsoleHost || *device != "" && *device != previous.Config.DeviceDomain {
			fmt.Fprintln(stderr, "Resume cannot change deployment domains")
			return 2
		}
		*console = previous.Config.ConsoleHost
		*device = previous.Config.DeviceDomain
	}
	if !prompt("Console DNS hostname", console) || !prompt("Device DNS base", device) || !prompt("New protected backup directory", backup) {
		fmt.Fprintln(stderr, "Initialization input is incomplete; no bundle was created")
		return 2
	}
	absSource, err := filepath.Abs(*source)
	if err != nil {
		fmt.Fprintln(stderr, "Invalid source directory")
		return 2
	}
	config := setup.Config{ConsoleHost: *console, DeviceDomain: *device, SourceDirectory: absSource, NetworkSubnet: *subnet}
	if *resume {
		config = previous.Config
	}
	if err = setup.Validate(config); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if !*skipDNS {
		address, err := netip.ParseAddr(*expected)
		if err != nil {
			fmt.Fprintln(stderr, "Provide --expected-address for DNS verification, or use --offline only for isolated preparation")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = setup.CheckDNS(ctx, config, address)
		cancel()
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
	}
	target, err := filepath.Abs(*directory)
	if err == nil && !*resume {
		target, err = setup.Generate(*directory, config)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Bundle creation failed; no existing files were overwritten. Inspect any partial private output before retrying.")
		return 1
	}
	backupPath, err := filepath.Abs(*backup)
	if err == nil {
		if *resume {
			if _, exists := os.Lstat(backupPath); exists == nil {
				err = setup.VerifyBackup(target, backupPath)
			} else {
				backupPath, err = setup.Backup(target, *backup)
			}
		} else {
			backupPath, err = setup.Backup(target, *backup)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "Secret backup failed. The private unconfirmed bundle is preserved; do not start the stack.")
		return 1
	}
	fmt.Fprintln(stderr, "Every generated secret has a checksum-verified copy in the requested backup directory. This local copy does not prove off-host durability. Preserve it on protected storage; no upstream can recover lost keys.")
	fmt.Fprintln(stderr, "After checking the backup, type: "+setup.BackupPhrase)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != setup.BackupPhrase {
		fmt.Fprintln(stderr, "Backup acknowledgement missing. The unconfirmed bundle and backup are preserved; do not start the stack.")
		return 1
	}
	if err = setup.Confirm(target, backupPath, setup.BackupPhrase); err != nil {
		fmt.Fprintln(stderr, "Backup confirmation or container file ownership failed; do not start the stack.")
		return 1
	}
	fmt.Fprintln(stdout, "Deployment files prepared. Change into the requested deployment directory, then run:")
	fmt.Fprintln(stdout, "  docker compose build migrate postgres caddy")
	fmt.Fprintln(stdout, "  docker compose up -d")
	fmt.Fprintln(stdout, "  docker compose run --rm admin-bootstrap --email YOUR_EMAIL")
	fmt.Fprintln(stdout, "  nethub doctor --directory .")
	if *skipDNS {
		fmt.Fprintln(stdout, "Offline preparation only: verify DNS, public TLS, and external reachability before claiming deployment readiness.")
	}
	fmt.Fprintln(stdout, "W3 console stack only; device enrollment and relay services are added in W4.")
	return 0
}
