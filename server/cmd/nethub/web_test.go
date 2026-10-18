package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

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
