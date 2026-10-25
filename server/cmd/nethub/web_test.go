package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/providersecret"
)

func TestConsoleProviderKeyLoadingAndEarlyRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets_key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(key) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := loadProviderSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	binding := providersecret.Binding{TenantID: "fixture-tenant", ProviderID: "fixture-provider", Purpose: providersecret.OIDCClientSecret}
	plaintext := []byte("isolated console credential fixture")
	envelope, err := first.Seal(binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadProviderSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := second.Open(binding, envelope); err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatal("reloaded deployment key could not open its credential", err)
	}
	refuse := func() {
		t.Helper()
		if cipher, err := loadProviderSecrets(path); err != providersecret.ErrUnavailable || cipher != nil {
			t.Fatal("invalid console encryption key loaded")
		}
		var out, diagnostic bytes.Buffer
		args := []string{"web", "--password-file", "unused-database-password", "--origin", "https://console.example.com", "--device-domain", "router.example.com", "--secrets-key-file", path}
		if status := run(args, &out, &diagnostic); status != 1 || out.Len() != 0 || diagnostic.String() != "Console provider-encryption key is missing or invalid\n" {
			t.Fatal("console did not refuse its key before database startup", status)
		}
		if strings.Contains(diagnostic.String(), path) || strings.Contains(diagnostic.String(), strings.TrimSpace(encoded)) {
			t.Fatal("console diagnostic exposed key material or its private path")
		}
	}
	for _, invalid := range []string{"", strings.ToUpper("ab" + strings.TrimSpace(encoded)[2:]), strings.TrimSpace(encoded) + "00", "invalid-private-fixture", strings.Repeat("x", 129)} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		refuse()
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	refuse()
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, []byte(encoded), 0644); err != nil {
			t.Fatal(err)
		}
		refuse()
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := path + ".link"
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if cipher, err := loadProviderSecrets(link); err != providersecret.ErrUnavailable || cipher != nil {
			t.Fatal("console encryption key followed a link")
		}
	}
	t.Log("Console loaded the persistent 256-bit provider key and refused missing, malformed or unsafe material before database startup without exposing it")
}

func TestConsoleFlagsAndHelp(t *testing.T) {
	for _, args := range [][]string{{"web"}, {"web", "--port", "70000"}, {"web", "--trusted-proxy", "not-a-prefix"}, {"web", "--password-file", "fixture", "--device-domain", "router.example.com", "--origin", "http://console.example.com"}} {
		var out, diagnostic bytes.Buffer
		if status := run(args, &out, &diagnostic); status != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
			t.Fatalf("invalid flags: status=%d", status)
		}
	}
	var out, diagnostic bytes.Buffer
	if status := run([]string{"web", "--help"}, &out, &diagnostic); status != 0 || diagnostic.Len() == 0 {
		t.Fatal("console help did not succeed")
	}
}

func TestConsoleGracefulShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }), ReadHeaderTimeout: time.Second}
	result := make(chan error, 1)
	go func() { result <- serveHTTP(ctx, server, listener) }()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(data) != "ok" {
		t.Fatal("console did not serve a request")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("console did not shut down")
	}
	client.CloseIdleConnections()
}
