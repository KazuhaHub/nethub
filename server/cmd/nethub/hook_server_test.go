package main

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

func TestHookServerKeepsBoundsAndOutlastsFrpsPluginClient(t *testing.T) {
	server := newHookServer(http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if server.IdleTimeout != relayhook.ServerIdleTimeout {
		t.Fatalf("hook server idle timeout %s, want %s", server.IdleTimeout, relayhook.ServerIdleTimeout)
	}
	if server.ReadHeaderTimeout != time.Second || server.ReadTimeout != time.Second ||
		server.WriteTimeout != 2*time.Second || server.MaxHeaderBytes != 16*1024 || server.ErrorLog == nil {
		t.Fatal("hook server header/body/write bounds changed")
	}
}
