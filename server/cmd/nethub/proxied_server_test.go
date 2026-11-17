package main

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// caddyUpstreamIdleTimeout is the reverse_proxy keep-alive default in the
// pinned Caddy (modules/caddyhttp/reverseproxy/httptransport.go, v2.11.9).
const caddyUpstreamIdleTimeout = 2 * time.Minute

func TestProxiedServerOutlastsBundledCaddyKeepAlive(t *testing.T) {
	module, err := os.ReadFile("../../../deploy/images/caddy/go.mod")
	if err != nil {
		t.Fatal("bundled Caddy module file is unreadable")
	}
	if !strings.Contains(string(module), "\tgithub.com/caddyserver/caddy/v2 v2.11.9\n") {
		t.Fatal("bundled Caddy version changed; re-check its reverse_proxy keep-alive default")
	}
	for _, name := range []string{"../../../deploy/Caddyfile", "../../internal/setup/templates/Caddyfile"} {
		config, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("Caddy configuration %s is unreadable", name)
		}
		if strings.Contains(string(config), "transport") || strings.Contains(string(config), "keepalive") {
			t.Fatalf("Caddy configuration %s overrides the upstream transport; re-check its keep-alive", name)
		}
	}
	if proxiedServerIdleTimeout < caddyUpstreamIdleTimeout+caddyUpstreamIdleTimeout/4 {
		t.Fatalf("proxied server idle timeout %s must clearly exceed the Caddy upstream idle timeout %s",
			proxiedServerIdleTimeout, caddyUpstreamIdleTimeout)
	}
	server := newProxiedServer(http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if server.IdleTimeout != proxiedServerIdleTimeout {
		t.Fatalf("proxied server idle timeout %s, want %s", server.IdleTimeout, proxiedServerIdleTimeout)
	}
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 20*time.Second || server.MaxHeaderBytes != 16*1024 || server.ErrorLog == nil {
		t.Fatal("proxied server header/body/write bounds changed")
	}
}
