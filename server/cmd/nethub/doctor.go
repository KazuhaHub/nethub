package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/setup"
)

func runDoctor(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", ".", "Initialized deployment directory")
	healthURL := flags.String("health-url", "", "Check a private loopback HTTP health endpoint only")
	expected := flags.String("expected-address", "", "Also check console/wildcard DNS against this address")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if *healthURL != "" {
		u, err := url.Parse(*healthURL)
		if err != nil {
			fmt.Fprintln(stderr, "Invalid health URL")
			return 2
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.IsLoopback() || u.Scheme != "http" || u.Path != "/healthz" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			fmt.Fprintln(stderr, "Health checks require an exact loopback HTTP /healthz URL")
			return 2
		}
		request, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
		defer client.CloseIdleConnections()
		response, err := client.Do(request)
		if err != nil {
			fmt.Fprintln(stderr, "Console health endpoint is unavailable")
			return 1
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 16))
		if err != nil || response.StatusCode != 200 || string(body) != "ok" {
			fmt.Fprintln(stderr, "Console health check failed")
			return 1
		}
		fmt.Fprintln(stdout, "Console database health passed")
		return 0
	}
	if err := setup.CheckFiles(*directory); err != nil {
		fmt.Fprintln(stderr, "Deployment file check failed: "+err.Error())
		return 1
	}
	fmt.Fprintln(stdout, "Secret checksums, independent backup coverage, and service ownership passed")
	if *expected != "" {
		manifest, err := setup.Load(*directory)
		if err != nil {
			return 1
		}
		ip, err := netip.ParseAddr(*expected)
		if err != nil {
			fmt.Fprintln(stderr, "Invalid expected DNS address")
			return 2
		}
		if err = setup.CheckDNS(ctx, manifest.Config, ip); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		fmt.Fprintln(stdout, "Console and random wildcard DNS probes passed")
	}
	fmt.Fprintln(stdout, "Not checked: public port reachability, public TLS issuance, runtime mounts/database grants, relay/authz health, and scheduled database backup. Complete stage acceptance separately.")
	return 0
}
