package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
	"github.com/KazuhaHub/nethub/server/internal/relaystate"
)

func testAuthzRuntime(t *testing.T, f *enrollmentFixture, webRole *sql.DB, tenant string) {
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
	const adminUser = "test-admin"
	const adminPassword = "public-test-only-admin-observation-password"
	var adminData atomic.Value
	adminData.Store([]byte(`{"proxies":[]}`))
	adminRequests := make(chan time.Time, 8)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != adminUser || password != adminPassword || r.Method != http.MethodGet || r.URL.RequestURI() != "/api/proxy/https" {
			t.Error("runtime observation sent an invalid admin request")
			w.WriteHeader(401)
			return
		}
		select {
		case adminRequests <- time.Now():
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(adminData.Load().([]byte))
	}))
	defer admin.Close()
	directory := t.TempDir()
	for name, value := range map[string]string{"claim_key": key, "frp_token": relay.FRPToken, "relay_ca.pem": relay.RelayCAPEM,
		"frps_admin_user": adminUser, "frps_admin_password": adminPassword} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	hookSocket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	hookAddress := hookSocket.Addr().String()
	listener.Close()
	hookSocket.Close()
	command := exec.CommandContext(f.ctx, binary, "authz", "--host", "127.0.0.1", "--sslmode", "disable",
		"--password-file", "/run/secrets/pg_nethub_authz", "--origin", "https://console.example.com",
		"--listen", address, "--claim-key-id", "integration", "--claim-key-file", filepath.Join(directory, "claim_key"),
		"--frp-token-file", filepath.Join(directory, "frp_token"), "--relay-ca-file", filepath.Join(directory, "relay_ca.pem"),
		"--relay-addr", relay.ServerAddr, "--relay-server-name", relay.ServerName,
		"--device-domain", "devices.example.com",
		"--hook-listen", hookAddress, "--hook-peer", "127.0.0.1",
		"--frps-admin-origin", admin.URL, "--frps-admin-user-file", filepath.Join(directory, "frps_admin_user"),
		"--frps-admin-password-file", filepath.Join(directory, "frps_admin_password"))
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Fatal("authz CLI lacks execution permission in the test container")
		}
		if errors.Is(err, os.ErrNotExist) {
			t.Fatal("authz CLI is missing from the test container")
		}
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
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&certificateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	input.GUIPublicKey = base64.RawURLEncoding.EncodeToString(public)
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
	certificatePost := testRuntimeCertificateRequest(t, f, client, address, result, certificateKey)
	observation, err := json.Marshal(map[string]any{"proxies": []map[string]any{{"name": relayhook.ProxyName(result.DeviceID), "status": "online",
		"conf": map[string]string{"name": relayhook.ProxyName(result.DeviceID), "type": "https", "subdomain": result.Subdomain}}}})
	if err != nil {
		t.Fatal(err)
	}
	adminData.Store(observation)
	metas := map[string]string{"device_id": result.DeviceID, "domain_claim": result.DomainClaim}
	sendHook := func(target, operation string, content map[string]any, rejected bool, status int) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"version": "0.1.0", "op": operation, "content": content})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, "http://"+target+relayhook.Path+"?op="+operation+"&version=0.1.0", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "console.example.com"
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("runtime callback request failed")
		}
		defer response.Body.Close()
		var decision struct {
			Reject bool   `json:"reject"`
			Reason string `json:"reject_reason"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&decision) != nil ||
			response.StatusCode != status || status == 200 && decision.Reject != rejected {
			t.Fatal("runtime callback returned an incorrect decision or crossed listeners")
		}
	}
	login := map[string]any{"metas": metas}
	ping := map[string]any{"user": map[string]any{"metas": metas}, "timestamp": 1}
	proxy := map[string]any{"user": map[string]any{"metas": metas}, "proxy_name": relayhook.ProxyName(result.DeviceID), "proxy_type": "https", "subdomain": result.Subdomain}
	sendHook(hookAddress, "Login", login, false, 200)
	sendHook(hookAddress, "Ping", ping, false, 200)
	sendHook(hookAddress, "NewProxy", proxy, false, 200)
	proxy["custom_domains"] = []string{"console.example.com"}
	sendHook(hookAddress, "NewProxy", proxy, true, 200)
	delete(proxy, "custom_domains")
	// The public listener cannot invoke relay callbacks, even with a valid claim.
	sendHook(address, "Login", login, true, 404)
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, result.DeviceID); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	sendHook(hookAddress, "Login", login, true, 200)
	if elapsed := time.Since(started); elapsed < relayhook.Budget/2 || elapsed > 1500*time.Millisecond {
		t.Fatal("runtime did not bound a real device-row lock wait")
	}
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	sendHook(hookAddress, "Login", login, false, 200)
	var firstPoll, secondPoll time.Time
	for _, observed := range []*time.Time{&firstPoll, &secondPoll} {
		select {
		case *observed = <-adminRequests:
		case <-time.After(25 * time.Second):
			t.Fatal("runtime did not poll the admin API at its production cadence")
		}
	}
	if elapsed := secondPoll.Sub(firstPoll); elapsed < 4*time.Second || elapsed > 8*time.Second {
		t.Fatal("runtime did not use the configured five-second observation cadence")
	}
	seen := false
	// A scheduled observation can skip the row during the deliberate lock above.
	for deadline := time.Now().Add(relaystate.Interval + 3*time.Second); time.Now().Before(deadline); {
		if err := f.owner.QueryRowContext(f.ctx, `SELECT coalesce(last_seen_at BETWEEN statement_timestamp()-interval '5 seconds' AND statement_timestamp(),false) FROM devices WHERE id=$1`, result.DeviceID).Scan(&seen); err != nil {
			t.Fatal(err)
		}
		if seen {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !seen {
		t.Fatal("compiled runtime did not persist a matching periodic relay observation")
	}
	t.Log("Compiled authz observation passed its five-second production cadence with persisted device state")
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, result.DeviceID); err != nil {
		t.Fatal(err)
	}
	if status, _ := certificatePost("settings", protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: result.DeviceID}); status != 401 {
		t.Fatal("compiled certificate API returned data after revocation")
	}
	var cancelled int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_jobs WHERE device_id=$1 AND generation=1 AND state='cancelled' AND lease_token IS NULL`, result.DeviceID).Scan(&cancelled); err != nil || cancelled != 1 {
		t.Fatal("compiled admission's queued work survived device revocation", err)
	}
	sendHook(hookAddress, "Login", login, true, 200)
	sendHook(hookAddress, "NewProxy", proxy, true, 200)
	// The production refresh interval must publish revocation without another Login.
	deadline := time.Now().Add(relayhook.RevocationInterval + 2*time.Second)
	for {
		data, err := json.Marshal(map[string]any{"version": "0.1.0", "op": "Ping", "content": ping})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, "http://"+hookAddress+relayhook.Path+"?op=Ping&version=0.1.0", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("compiled Ping failed", err)
		}
		var decision struct {
			Reject bool   `json:"reject"`
			Reason string `json:"reject_reason"`
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&decision)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 {
			t.Fatal("compiled Ping response invalid")
		}
		if decision.Reject {
			if decision.Reason != "not_authorized" {
				t.Fatal("compiled Ping failed for a non-revocation reason")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("compiled revocation refresh exceeded production interval")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Log("Compiled authz Ping used its initialized memory snapshot and published revocation on the five-second production refresh interval")
	consoleRepo := &ConsoleStore{AuthStore: AuthStore{DB: webRole, Tenant: tenant}}
	requestReceipt, err := consoleRepo.RequestDisconnect(f.ctx, actor, result.DeviceID, netip.MustParseAddr("192.0.2.188"))
	if err != nil {
		t.Fatal("compiled runtime cutoff request failed", err)
	}
	deadline = time.Now().Add(relayhook.RevocationInterval + 3*time.Second)
	for {
		var armed bool
		if err = f.owner.QueryRowContext(f.ctx, `SELECT processed_at IS NOT NULL FROM device_disconnect_requests WHERE id=$1`, requestReceipt.RequestID).Scan(&armed); err != nil {
			t.Fatal(err)
		}
		if armed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("compiled authz did not process the pending cutoff")
		}
		time.Sleep(25 * time.Millisecond)
	}
	var armedAudits int
	if err = f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.disconnect_armed' AND payload->>'request_id'=$2`, result.DeviceID, requestReceipt.RequestID).Scan(&armedAudits); err != nil || armedAudits != 1 {
		t.Fatal("compiled cutoff lacks one processing audit", err)
	}
	t.Log("Compiled authz processed the genuine web-role cutoff request only after published Ping denial with one armed audit")
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
	for _, secret := range []string{key, relay.FRPToken, token, result.DeviceSecret, result.DomainClaim, adminPassword} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("authz process exposed credential material in its output")
		}
	}
}
