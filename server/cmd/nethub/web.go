package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/store"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/KazuhaHub/nethub/server/internal/webui"
)

type proxyFlags []netip.Prefix

func (p *proxyFlags) String() string {
	parts := []string{}
	for _, prefix := range *p {
		parts = append(parts, prefix.String())
	}
	return strings.Join(parts, ",")
}

func (p *proxyFlags) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Is4In6() {
		return errors.New("trusted-proxy requires an IPv4 or IPv6 CIDR")
	}
	*p = append(*p, prefix.Masked())
	return nil
}

func runWeb(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	flags.SetOutput(stderr)
	host := flags.String("host", "postgres", "Database hostname")
	port := flags.Uint("port", 5432, "Database port")
	database := flags.String("database", "nethub", "Database name")
	passwordFile := flags.String("password-file", "", "Web-role password file")
	secretsKeyFile := flags.String("secrets-key-file", "/run/secrets/secrets_key", "Private deployment provider-encryption key file")
	tls := flags.String("sslmode", "verify-full", "verify-full, or disable for an isolated local database")
	listen := flags.String("listen", "127.0.0.1:8080", "Private console listen address")
	origin := flags.String("origin", "", "External HTTPS console origin, without a path")
	deviceDomain := flags.String("device-domain", "", "Device DNS domain without a wildcard prefix")
	idle := flags.Duration("idle-timeout", 30*time.Minute, "Session idle timeout")
	absolute := flags.Duration("session-timeout", 12*time.Hour, "Absolute session timeout")
	var proxies proxyFlags
	flags.Var(&proxies, "trusted-proxy", "Trusted proxy CIDR; repeat for multiple proxies")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *port == 0 || *port > 65535 || *passwordFile == "" || *secretsKeyFile == "" || *origin == "" || *deviceDomain == "" {
		fmt.Fprintln(stderr, "web requires an origin, device domain, web password file, and valid database settings")
		return 2
	}
	if _, err := auth.NewOriginPolicy(*origin); err != nil {
		fmt.Fprintln(stderr, "Console origin must be an absolute HTTPS origin without a path")
		return 2
	}
	providerSecrets, err := loadProviderSecrets(*secretsKeyFile)
	if err != nil {
		fmt.Fprintln(stderr, "Console provider-encryption key is missing or invalid")
		return 1
	}
	if !webui.Ready() {
		fmt.Fprintln(stderr, "Build the console assets before starting web")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db, err := store.OpenRole(startup, store.DatabaseConfig{Host: *host, Port: uint16(*port), Database: *database, PasswordFile: *passwordFile, SSLMode: *tls}, "nethub_web")
	if err != nil {
		fmt.Fprintln(stderr, "Console database connection failed; check settings and the web password file")
		return 1
	}
	defer db.Close()
	tenant, err := store.SoleTenant(startup, db)
	if err != nil {
		fmt.Fprintln(stderr, "Console startup requires migrated tables and exactly one tenant")
		return 1
	}
	repository := &store.ConsoleStore{AuthStore: store.AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: providerSecrets}
	service, err := auth.NewService(&repository.AuthStore, auth.Config{IdleTimeout: *idle, AbsoluteTimeout: *absolute})
	if err != nil {
		fmt.Fprintln(stderr, "Console authentication configuration is invalid")
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	handler, err := web.New(web.Config{Origin: *origin, DeviceDomain: *deviceDomain, TrustedProxies: proxies, Logger: logger}, service, repository)
	if err != nil {
		fmt.Fprintln(stderr, "Console origin, domain, or proxy configuration is invalid")
		return 1
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "Console listener could not be opened")
		return 1
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
	fmt.Fprintln(stdout, "Console API started")
	if err := serveHTTP(ctx, server, listener); err != nil {
		fmt.Fprintln(stderr, "Console HTTP service stopped unexpectedly")
		return 1
	}
	return 0
}

func loadProviderSecrets(path string) (*providersecret.Cipher, error) {
	key, err := readAuthzHex(path)
	if err != nil {
		return nil, providersecret.ErrUnavailable
	}
	defer clear(key)
	return providersecret.New(key)
}

func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener) error {
	defer listener.Close()
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
			return err
		}
		err := <-result
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
