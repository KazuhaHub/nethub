package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbePreservesTLSAndRefusesOtherDestinations(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "fixture")
	if err := prepare(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(directory, "origin.crt"), filepath.Join(directory, "origin.key"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS.ServerName != "dex-one.test" || r.Host != "dex-one.test" {
			t.Error("fixture lost its original SNI or Host")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(directory, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := probeTransport(root, port)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://dex-one.test/")
	if err != nil {
		t.Fatal("normal TLS failed", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || requests.Load() != 1 {
		t.Fatal("trusted fixture origin was not reached")
	}
	for _, url := range []string{"https://wrong.test/", "https://dex-one.test:8443/", "http://dex-one.test/", "https://127.0.0.1/"} {
		if response, err := client.Get(url); err == nil {
			response.Body.Close()
			t.Fatal("probe accepted an unintended destination", url)
		}
	}
	other := filepath.Join(t.TempDir(), "different-fixture")
	if err := prepare(other, time.Now()); err != nil {
		t.Fatal(err)
	}
	otherRoot, err := os.ReadFile(filepath.Join(other, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := probeTransport(otherRoot, port)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.CloseIdleConnections()
	if response, err := (&http.Client{Transport: untrusted, Timeout: 5 * time.Second}).Get("https://dex-one.test/"); err == nil {
		response.Body.Close()
		t.Fatal("probe bypassed its trusted CA")
	}
	if requests.Load() != 1 {
		t.Fatal("a refused connection reached HTTP")
	}
}
