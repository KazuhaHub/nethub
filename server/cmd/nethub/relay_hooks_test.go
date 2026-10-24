package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestRevocationWorkerFailureStopsBothAuthorizationListeners(t *testing.T) {
	for _, failure := range []error{errors.New("self-check failed"), nil} {
		publicListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		hookListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			publicListener.Close()
			t.Fatal(err)
		}
		public := &http.Server{Handler: http.NotFoundHandler()}
		hooks := &http.Server{Handler: http.NotFoundHandler()}
		trigger := make(chan struct{})
		worker := func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return nil
			case <-trigger:
				return failure
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- serveAuthzMonitored(ctx, public, publicListener, hooks, hookListener, worker) }()
		close(trigger)
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("unexpected worker exit was treated as a clean stop")
			}
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("worker failure did not stop the APIs")
		}
		cancel()
		for _, listener := range []net.Listener{publicListener, hookListener} {
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
			if err == nil {
				connection.Close()
				t.Fatal("authorization listener remained available")
			}
		}
	}
}

func TestHookListenerRequiresPrivateBindAndExactPeers(t *testing.T) {
	var peers hookPeers
	if err := peers.Set("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1:9000", "[::1]:9000", "[fd00::1]:9000"} {
		if !validHookListener(address, peers) {
			t.Fatal("private callback listener was rejected")
		}
	}
	for _, address := range []string{"", ":9000", net.JoinHostPort(netip.IPv4Unspecified().String(), "9000"), "[::]:9000", "192.0.2.1:9000", "relay.example.com:9000", "127.0.0.1:70000"} {
		if validHookListener(address, peers) {
			t.Fatal("callback listener accepted an unsafe bind or invalid port")
		}
	}
	if !validHookListener("", nil) || validHookListener("127.0.0.1:9000", nil) {
		t.Fatal("callback enablement and peer configuration are inconsistent")
	}
	for _, address := range []string{"127.0.0.1/32", "relay.example.com", "::", "fe80::1%zone"} {
		if err := peers.Set(address); err == nil {
			t.Fatal("invalid callback peer accepted")
		}
	}
	if peers[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("invalid peer input mutated the peer configuration")
	}
}

func TestBothAuthorizationListenersStopTogether(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		publicListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		hookListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			publicListener.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		public := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
		hooks := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
		done := make(chan error, 1)
		go func() { done <- serveAuthz(ctx, public, publicListener, hooks, hookListener) }()
		client := &http.Client{Timeout: time.Second}
		for _, listener := range []net.Listener{publicListener, hookListener} {
			response, err := client.Get("http://" + listener.Addr().String() + "/test")
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			response.Body.Close()
		}
		client.CloseIdleConnections()
		if unexpected {
			_ = hooks.Close()
		} else {
			cancel()
		}
		select {
		case err := <-done:
			if unexpected != (err != nil) {
				t.Error("listener failure did not change the runtime result")
			}
		case <-time.After(3 * time.Second):
			t.Error("authorization listeners did not stop together")
		}
		cancel()
		public.Close()
		hooks.Close()
	}
}
