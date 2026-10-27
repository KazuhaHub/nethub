package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/setup"
	"github.com/KazuhaHub/nethub/server/internal/store"
)

func runDoctor(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", ".", "Initialized deployment directory")
	healthURL := flags.String("health-url", "", "Check a private loopback HTTP health endpoint only")
	expected := flags.String("expected-address", "", "Also check console/wildcard DNS against this address")
	publicTLS := flags.Bool("public-tls", false, "Verify the initialized console hostname on TCP 443 with system certificate trust")
	audit := flags.Bool("audit", false, "Verify the deployment audit chain in a read-only database snapshot")
	roles := flags.Bool("database-roles", false, "Check runtime role and device identity privileges through the Web database identity")
	containers := flags.Bool("runtime-containers", false, "Inspect existing protected Linux Docker service separation without modifying services")
	project := flags.String("project", "nethub", "Existing Compose project for runtime container inspection")
	composeFile := flags.String("compose-file", "", "Optional protected Compose override for runtime container inspection")
	host := flags.String("host", "postgres", "Database hostname for read-only checks")
	port := flags.Uint("port", 5432, "Database port for read-only checks")
	database := flags.String("database", "nethub", "Database name for read-only checks")
	passwordFile := flags.String("password-file", "", "Web-role password file for read-only database checks")
	tls := flags.String("sslmode", "verify-full", "verify-full, or disable for an isolated local database")
	legacyZone := flags.String("audit-timezone", "UTC", "Original writer timezone for legacy audit records")
	auditTimeout := flags.Duration("audit-timeout", 30*time.Second, "Total audit check budget, between one second and five minutes")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	selected := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { selected[f.Name] = true })
	if *containers {
		for name := range selected {
			if name != "runtime-containers" && name != "directory" && name != "project" && name != "compose-file" {
				fmt.Fprintln(stderr, "Run container inspection separately from database, DNS, certificate and health checks")
				return 2
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := setup.CheckRuntimeContainers(ctx, *directory, *project, *composeFile); err != nil {
			fmt.Fprintln(stderr, "Runtime container separation check failed; run on the Linux Docker host as root, verify the protected deployment/project and restore reviewed service users, images, environment, read-only mounts and secret directories; no service was changed")
			return 1
		}
		fmt.Fprintln(stdout, "Running Web/authz/frps container separation and reviewed Web secret mount passed; inspection did not modify services")
		fmt.Fprintln(stdout, "Not checked: database privileges, actual hook traffic, external reachability, recent database backup or version agreement")
		return 0
	}
	if selected["project"] || selected["compose-file"] {
		fmt.Fprintln(stderr, "Compose selection requires doctor --runtime-containers")
		return 2
	}
	if *audit || *roles {
		if (*audit && *roles) || (*roles && (selected["audit-timezone"] || selected["audit-timeout"])) {
			fmt.Fprintln(stderr, "Run audit history and database role checks as separate modes")
			return 2
		}
		if selected["directory"] || selected["health-url"] || selected["expected-address"] || selected["public-tls"] || *passwordFile == "" ||
			*host == "" || *database == "" || *port == 0 || *port > 65535 || (*tls != "verify-full" && *tls != "disable") ||
			*legacyZone == "" || len(*legacyZone) > 64 || *auditTimeout < time.Second || *auditTimeout > 5*time.Minute {
			fmt.Fprintln(stderr, "Database checks require valid settings, a Web-role password file and a bounded timeout; run file/DNS/TLS/health checks separately")
			return 2
		}
		config := store.DatabaseConfig{Host: *host, Port: uint16(*port), Database: *database, PasswordFile: *passwordFile, SSLMode: *tls}
		if *roles {
			return runRoleDoctor(config, stdout, stderr)
		}
		return runAuditDoctor(auditDoctorOptions{Database: config, LegacyZone: *legacyZone, Timeout: *auditTimeout}, stdout, stderr)
	}
	for _, name := range []string{"host", "port", "database", "password-file", "sslmode", "audit-timezone", "audit-timeout"} {
		if selected[name] {
			fmt.Fprintln(stderr, "Database options require doctor --audit or --database-roles")
			return 2
		}
	}
	if *publicTLS && selected["health-url"] {
		fmt.Fprintln(stderr, "Run public TLS verification separately from private loopback health")
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
	if *publicTLS {
		manifest, err := setup.Load(*directory)
		if err != nil {
			fmt.Fprintln(stderr, "Console identity unavailable; restore the initialized deployment manifest before checking TLS")
			return 1
		}
		remaining, err := verifyConsoleTLS(ctx, net.JoinHostPort(manifest.Config.ConsoleHost, "443"), manifest.Config.ConsoleHost, nil, time.Now())
		if err != nil {
			fmt.Fprintln(stderr, "Console TLS verification failed; check DNS, TCP 443, the reverse proxy certificate chain and its renewal configuration")
			return 1
		}
		fmt.Fprintf(stdout, "Console certificate chain and hostname verified; %d whole days remaining\n", int64(remaining/(24*time.Hour)))
		if remaining < 30*24*time.Hour {
			fmt.Fprintln(stderr, "Console certificate expires within 30 days; check the reverse proxy renewal job and verify its next successful renewal")
			return 1
		}
		fmt.Fprintln(stdout, "Not checked: external port reachability, runtime mounts/database grants, relay/authz health, and scheduled database backup. Complete stage acceptance separately.")
	} else {
		fmt.Fprintln(stdout, "Not checked: public port reachability, public TLS issuance, runtime mounts/database grants, relay/authz health, and scheduled database backup. Complete stage acceptance separately.")
	}
	return 0
}
