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
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/device"
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
	handler, err := device.NewHTTP(device.HTTPConfig{Origin: *origin, TrustedProxies: proxies, Logger: logger}, service)
	if err != nil || service.Health(startup) != nil {
		fmt.Fprintln(stderr, "Authz origin, proxy configuration or database authorization is invalid")
		return 1
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "Authz listener could not be opened")
		return 1
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
	fmt.Fprintln(stdout, "Device enrollment API started; relay hooks are not implemented")
	if err := serveHTTP(ctx, server, listener); err != nil {
		fmt.Fprintln(stderr, "Authz HTTP service stopped unexpectedly")
		return 1
	}
	return 0
}
