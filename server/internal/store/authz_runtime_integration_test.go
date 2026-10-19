package store

import (
	"bytes"
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
)

func testAuthzRuntime(t *testing.T, f *enrollmentFixture, tenant string) {
	t.Helper()
	binary := os.Getenv("NETHUB_AUTHZ_TEST_BINARY")
	if binary == "" {
		t.Fatal("native harness must provide the compiled authz CLI")
	}
	data, err := os.ReadFile(filepath.Join(f.root, "examples/valid/enroll-response.json"))
	var relay protocol.EnrollResponse
	if err != nil || json.Unmarshal(data, &relay) != nil {
		t.Fatal("relay fixture is unavailable")
	}
	key := hex.EncodeToString(bytes.Repeat([]byte{17}, 32))
	directory := t.TempDir()
	for name, value := range map[string]string{"claim_key": key, "frp_token": relay.FRPToken, "relay_ca.pem": relay.RelayCAPEM} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	command := exec.CommandContext(f.ctx, binary, "authz", "--host", "127.0.0.1", "--sslmode", "disable",
		"--password-file", "/run/secrets/pg_nethub_authz", "--origin", "https://console.example.com",
		"--listen", address, "--claim-key-id", "integration", "--claim-key-file", filepath.Join(directory, "claim_key"),
		"--frp-token-file", filepath.Join(directory, "frp_token"), "--relay-ca-file", filepath.Join(directory, "relay_ca.pem"),
		"--relay-addr", relay.ServerAddr, "--relay-server-name", relay.ServerName)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		t.Fatal("authz CLI could not start")
	}
	completed := make(chan error, 1)
	go func() { completed <- command.Wait() }()
	exited := false
	defer func() {
		if !exited {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-completed:
				if err != nil {
					t.Error("authz did not exit cleanly after SIGTERM")
				}
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-completed
				t.Error("authz exceeded the graceful shutdown deadline")
			}
		}
	}()
	client := &http.Client{Timeout: 15 * time.Second}
	defer client.CloseIdleConnections()
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		select {
		case <-completed:
			exited = true
			t.Fatal("authz CLI exited before readiness")
		default:
		}
		response, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			body, readError := io.ReadAll(io.LimitReader(response.Body, 1024))
			response.Body.Close()
			if readError == nil && response.StatusCode == 200 && string(body) == "ok" {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("authz CLI did not become database/trust ready")
	}
	_, token, actor := f.fresh(t, tenant)
	input := f.input
	input.EnrollToken = token
	data, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, "http://"+address+"/api/v1/devices/enroll", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example.com"
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("authz process enrollment request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
	if err != nil || response.StatusCode != 201 || len(body) > protocol.MaxBodyBytes {
		t.Fatal("authz process did not return successful bounded enrollment output")
	}
	f.validateResponse(t, body)
	var result protocol.EnrollResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	payload, err := f.signer.Verify(result.DomainClaim)
	if err != nil || payload.DeviceID != result.DeviceID || payload.TenantID != tenant || result.FRPToken != relay.FRPToken {
		t.Fatal("runtime key/token file decoding does not match the committed protocol identity")
	}
	var storedActor string
	if err := f.owner.QueryRowContext(f.ctx, `SELECT owner_user_id FROM devices WHERE id=$1 AND tenant_id=$2`, result.DeviceID, tenant).Scan(&storedActor); err != nil || storedActor != actor {
		t.Fatal("runtime did not register with the token's owner and tenant")
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-completed:
		exited = true
		if err != nil {
			t.Fatal("authz process did not stop cleanly")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authz process shutdown timed out")
	}
	for _, secret := range []string{key, relay.FRPToken, token, result.DeviceSecret, result.DomainClaim} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("authz process exposed credential material in its output")
		}
	}
}
