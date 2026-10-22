package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
	"github.com/KazuhaHub/nethub/server/internal/relaystate"
	"github.com/KazuhaHub/nethub/server/internal/store"
)

func readAuthzFile(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit ||
		private && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("authorization material is missing or invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("authorization material is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("authorization material changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("authorization material is empty or exceeds its limit")
	}
	return data, nil
}

func readAuthzHex(path string) ([]byte, error) {
	data, err := readAuthzFile(path, 128, true)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(data))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return nil, errors.New("authorization secret must contain 32 lowercase hexadecimal bytes")
	}
	return decoded, nil
}

func runAuthz(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("authz", flag.ContinueOnError)
	flags.SetOutput(stderr)
	host := flags.String("host", "postgres", "Database hostname")
	port := flags.Uint("port", 5432, "Database port")
	database := flags.String("database", "nethub", "Database name")
	passwordFile := flags.String("password-file", "", "Authz-role password file")
	tls := flags.String("sslmode", "verify-full", "verify-full, or disable for an isolated local database")
	listen := flags.String("listen", "127.0.0.1:8081", "Private device API listen address")
	origin := flags.String("origin", "", "External HTTPS console origin without a path")
	claimFile := flags.String("claim-key-file", "", "Private deployment claim key file")
	keyID := flags.String("claim-key-id", "initial", "Active deployment claim key identifier")
	frpFile := flags.String("frp-token-file", "", "Private deployment frp token file")
	caFile := flags.String("relay-ca-file", "", "Public relay CA PEM bundle file")
	relayAddr := flags.String("relay-addr", "", "Relay control-channel hostname or IP")
	relayName := flags.String("relay-server-name", "", "Verified relay TLS server name")
	relayPort := flags.Uint("relay-port", 7000, "Relay control-channel port")
	deviceDomain := flags.String("device-domain", "", "Assigned device DNS suffix; enable certificate request admission")
	hookListen := flags.String("hook-listen", "", "Internal relay callback IP:port; enable with hook-peer")
	adminOrigin := flags.String("frps-admin-origin", "", "Private frps admin origin with an explicit port")
	adminUserFile := flags.String("frps-admin-user-file", "", "Private frps admin username file")
	adminPasswordFile := flags.String("frps-admin-password-file", "", "Private frps admin password file")
	var peers hookPeers
	flags.Var(&peers, "hook-peer", "Exact relay socket IP; repeat for multiple relays")
	var proxies proxyFlags
	flags.Var(&proxies, "trusted-proxy", "Trusted proxy CIDR; repeat for multiple proxies")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *port == 0 || *port > 65535 || *relayPort == 0 || *relayPort > 65535 ||
		*passwordFile == "" || *claimFile == "" || *frpFile == "" || *caFile == "" || *origin == "" || *relayAddr == "" || *relayName == "" {
		fmt.Fprintln(stderr, "Authz requires file-based credentials, relay trust, an HTTPS origin and valid ports")
		return 2
	}
	if _, err := auth.NewOriginPolicy(*origin); err != nil {
		fmt.Fprintln(stderr, "Authz origin must be an absolute HTTPS origin without a path")
		return 2
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		fmt.Fprintln(stderr, "Authz requires a valid private listen address")
		return 2
	}
	if !validHookListener(*hookListen, peers) {
		fmt.Fprintln(stderr, "Relay hooks require a private or loopback listen IP and exact relay peer addresses")
		return 2
	}
	if !validObservationFlags(*adminOrigin, *adminUserFile, *adminPasswordFile) {
		fmt.Fprintln(stderr, "Relay observation requires an admin origin and both credential file paths")
		return 2
	}
	key, keyError := readAuthzHex(*claimFile)
	frpToken, tokenError := readAuthzHex(*frpFile)
	ca, caError := readAuthzFile(*caFile, 32768, false)
	signer, signerError := claim.New(*keyID, map[string][]byte{*keyID: key})
	if keyError != nil || tokenError != nil || caError != nil || signerError != nil {
		fmt.Fprintln(stderr, "Authz signing key, relay token or public trust file is invalid")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db, err := store.OpenRole(startup, store.DatabaseConfig{Host: *host, Port: uint16(*port), Database: *database,
		PasswordFile: *passwordFile, SSLMode: *tls}, "nethub_authz")
	if err != nil {
		fmt.Fprintln(stderr, "Authz database connection failed; check settings and the authz password file")
		return 1
	}
	defer db.Close()
	repository := &store.EnrollmentStore{DB: db}
	service, err := device.New(repository, signer, device.RelayConfig{Address: *relayAddr, ServerName: *relayName,
		Port: uint16(*relayPort), FRPToken: hex.EncodeToString(frpToken), CAPEM: string(ca)})
	if err != nil {
		fmt.Fprintln(stderr, "Authz relay identity or trust configuration is invalid")
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	var certificates *device.CertificateService
	if *deviceDomain != "" {
		console, parseErr := url.Parse(*origin)
		if parseErr != nil || strings.EqualFold(console.Hostname(), *deviceDomain) || strings.HasSuffix(strings.ToLower(console.Hostname()), "."+*deviceDomain) {
			fmt.Fprintln(stderr, "Console origin must be outside the device certificate domain")
			return 1
		}
		requests := &store.GUIRequestStore{Enrollment: repository, DeviceDomain: *deviceDomain}
		certificates, err = device.NewCertificates(service, &store.GUIJobQueue{Requests: requests})
		if err != nil || certificates.Health(startup) != nil {
			fmt.Fprintln(stderr, "Certificate admission domain or database authorization is invalid")
			return 1
		}
	}
	trust, err := device.NewRelayTrust(service, &store.RelayTrustStore{Enrollment: repository, ServerName: *relayName})
	if err != nil || trust.Health(startup) != nil {
		fmt.Fprintln(stderr, "Relay trust database authorization is unavailable")
		return 1
	}
	handler, err := device.NewHTTP(device.HTTPConfig{Origin: *origin, TrustedProxies: proxies, Logger: logger, Certificates: certificates, RelayTrust: trust}, service)
	if err != nil || service.Health(startup) != nil {
		fmt.Fprintln(stderr, "Authz origin, proxy configuration or database authorization is invalid")
		return 1
	}
	var observer *relaystate.Poller
	if *adminOrigin != "" {
		observer, err = newObserver(*adminOrigin, *adminUserFile, *adminPasswordFile, db, logger)
		if err != nil {
			fmt.Fprintln(stderr, "Relay observation origin or credential configuration is invalid")
			return 1
		}
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "Authz listener could not be opened")
		return 1
	}
	defer listener.Close()
	var hooks *http.Server
	var hookListener net.Listener
	if *hookListen != "" {
		hookHandler, err := relayhook.New(relayhook.Config{Peers: peers, Logger: logger}, &store.RelayStore{DB: db}, signer)
		if err != nil {
			fmt.Fprintln(stderr, "Relay callback configuration is invalid")
			return 1
		}
		hookListener, err = net.Listen("tcp", *hookListen)
		if err != nil {
			fmt.Fprintln(stderr, "Relay callback listener could not be opened")
			return 1
		}
		defer hookListener.Close()
		hooks = &http.Server{Handler: hookHandler, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second,
			WriteTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
			ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
	if observer != nil {
		observationContext, stopObservation := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { observer.Run(observationContext); close(done) }()
		defer func() { stopObservation(); <-done }()
		fmt.Fprintln(stdout, "Read-only relay observation enabled")
	}
	if hooks == nil {
		fmt.Fprintln(stdout, "Device enrollment API started; relay hooks disabled")
	} else {
		fmt.Fprintln(stdout, "Device enrollment API and internal relay hooks started")
	}
	if err := serveAuthz(ctx, server, listener, hooks, hookListener); err != nil {
		fmt.Fprintln(stderr, "Authz HTTP service stopped unexpectedly")
		return 1
	}
	return 0
}
