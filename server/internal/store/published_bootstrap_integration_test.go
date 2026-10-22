package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

func testPublishedBootstrapRuntime(t *testing.T, f *enrollmentFixture, tenant string, bootstrap protocol.EnrollResponse, current *relaytrust.Generation) {
	t.Helper()
	binary := os.Getenv("NETHUB_AUTHZ_TEST_BINARY")
	if binary == "" {
		t.Fatal("genuine published-bootstrap test requires the compiled authz CLI")
	}
	ctx, cancel := context.WithTimeout(f.ctx, 25*time.Second)
	defer cancel()
	directory := t.TempDir()
	key := hex.EncodeToString(bytes.Repeat([]byte{17}, 32))
	for name, raw := range map[string]string{"claim-key": key, "frp-token": bootstrap.FRPToken, "expired-ca.pem": bootstrap.RelayCAPEM} {
		if os.WriteFile(filepath.Join(directory, name), []byte(raw), 0600) != nil {
			t.Fatal("private compiled-bootstrap input")
		}
	}
	listen := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("private runtime listener")
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	address, hook := listen(), listen()
	output, err := os.CreateTemp(directory, "runtime-private-*.log")
	if err != nil {
		t.Fatal("private runtime diagnostic file")
	}
	defer output.Close()
	command := exec.CommandContext(ctx, binary, "authz", "--host", "127.0.0.1", "--sslmode", "disable", "--password-file", "/run/secrets/pg_nethub_authz", "--origin", "https://console.example.com", "--listen", address,
		"--claim-key-id", "integration", "--claim-key-file", filepath.Join(directory, "claim-key"), "--frp-token-file", filepath.Join(directory, "frp-token"), "--relay-ca-file", filepath.Join(directory, "expired-ca.pem"),
		"--relay-addr", bootstrap.ServerAddr, "--relay-server-name", current.ServerName, "--hook-listen", hook, "--hook-peer", "127.0.0.1")
	command.Stdout, command.Stderr = output, output
	command.WaitDelay = 2 * time.Second
	if command.Start() != nil {
		t.Fatal("compiled bootstrap runtime did not start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Error("published-bootstrap runtime did not stop cleanly")
			}
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("published-bootstrap runtime exceeded shutdown deadline")
		}
		stopped = true
	}
	defer stop()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	ready := false
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		select {
		case <-done:
			stopped = true
			t.Fatal("runtime exited despite current valid database publication")
		default:
		}
		response, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		t.Fatal("expired mounted bootstrap prevented current-publication readiness")
	}
	post := func(path, secret string, input any) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal("runtime public request fixture")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal("runtime fixture request construction")
		}
		request.Host = "console.example.com"
		request.Header.Set("Content-Type", "application/json")
		if secret != "" {
			request.Header.Set("Authorization", "Bearer "+secret)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("compiled current-publication request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
		if err != nil || len(body) > protocol.MaxBodyBytes || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("runtime trust response was oversized or cacheable")
		}
		return response.StatusCode, body
	}
	_, token, _ := f.fresh(t, tenant)
	input := f.input
	input.EnrollToken = token
	status, body := post("/api/v1/devices/enroll", "", input)
	var enrolled protocol.EnrollResponse
	if status != http.StatusCreated || json.Unmarshal(body, &enrolled) != nil || enrolled.RelayCAPEM != current.Bundle().PEM() || enrolled.RelayCAPEM == bootstrap.RelayCAPEM || enrolled.ServerName != current.ServerName {
		t.Fatal("compiled enrollment did not select current transactional trust")
	}
	f.validateResponse(t, body)
	identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: enrolled.DeviceID}
	status, body = post("/api/v1/devices/relay-trust/settings", enrolled.DeviceSecret, identity)
	var settings protocol.RelayTrustSettings
	if status != http.StatusOK || json.Unmarshal(body, &settings) != nil || settings.Desired == nil || settings.Desired.ID != current.ID || settings.Desired.CAPEM != current.Bundle().PEM() {
		t.Fatal("compiled authenticated recovery delivered stale trust")
	}
	if _, err := f.owner.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, enrolled.DeviceID); err != nil {
		t.Fatal("revoke compiled-bootstrap fixture", err)
	}
	if status, _ := post("/api/v1/devices/relay-trust/settings", enrolled.DeviceSecret, identity); status != http.StatusUnauthorized {
		t.Fatal("compiled trust recovery bypassed revocation")
	}
	stop()
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal("private runtime diagnostics unavailable")
	}
	logs, err := io.ReadAll(io.LimitReader(output, 65537))
	if err != nil || len(logs) > 65536 {
		t.Fatal("runtime diagnostic output exceeded its test bound")
	}
	for _, secret := range []string{key, bootstrap.FRPToken, token, enrolled.DeviceSecret, enrolled.DomainClaim} {
		if strings.Contains(string(logs), secret) {
			t.Fatal("published-bootstrap runtime logged credentials")
		}
	}
	t.Log("Compiled authz passed expired mounted bootstrap startup, genuine current-publication readiness, transaction-selected enrollment, authenticated trust recovery and revocation denial; private HTTP fixture, no native application")
}
