package guiacme_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type hostEnrolledDevice struct {
	settings protocol.CertificateSettings
	csr      []byte
	post     func(string, any) (int, []byte)
}

// Only the initial tenant/user/token authority is administrative fixture data.
// Device registration, public CSR admission and generation-one queueing all use
// the compiled production HTTP server with its real restricted database role.
func enrollHostDevice(t *testing.T, directory, nonce string, binding guiissuer.DockerBinding, run guiissuer.SQLRunner, must func([]byte, string, ...string) []byte) hostEnrolledDevice {
	t.Helper()
	for _, file := range []struct{ source, target string }{
		{"secrets/authz/claim_key", "/tmp/nethub-host-claim"},
		{"secrets/authz/frp_token", "/tmp/nethub-host-frp"},
		{"runtime/trust/relay-ca.pem", "/tmp/nethub-host-relay-ca.pem"},
	} {
		must(nil, "/usr/bin/docker", "cp", filepath.Join(directory, file.source), binding.ContainerID+":"+file.target)
		must(nil, "/usr/bin/docker", "exec", binding.ContainerID, "chown", "postgres:postgres", file.target)
		must(nil, "/usr/bin/docker", "exec", binding.ContainerID, "chmod", "0600", file.target)
	}
	address := string(must(nil, "/usr/bin/docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", binding.ContainerID))
	if ip := net.ParseIP(address); ip == nil || !ip.IsPrivate() {
		t.Fatal("authz fixture must remain on its private Compose bridge")
	}
	must(nil, "/usr/bin/docker", "exec", "--detach", "--user", "postgres", binding.ContainerID, "/tmp/nethub-host-fixture", "authz",
		"--host", "127.0.0.1", "--sslmode", "disable", "--password-file", "/run/secrets/pg_nethub_authz",
		"--listen", ":18082", "--origin", "https://console.example.test", "--device-domain", "devices.example.test",
		"--claim-key-id", "fixture", "--claim-key-file", "/tmp/nethub-host-claim", "--frp-token-file", "/tmp/nethub-host-frp",
		"--relay-ca-file", "/tmp/nethub-host-relay-ca.pem", "--relay-addr", "console.example.test", "--relay-server-name", "console.example.test",
		"--hook-listen", "127.0.0.1:19000", "--hook-peer", "127.0.0.1")
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	origin := "http://" + net.JoinHostPort(address, "18082")
	deadline := time.Now().Add(12 * time.Second)
	for {
		r, _ := http.NewRequest(http.MethodGet, origin+"/healthz", nil)
		r.Host = "console.example.test"
		response, err := client.Do(r)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("private compiled authz fixture did not become ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	post := func(path string, input any, secret string) (int, []byte) {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal("private device fixture encoding")
		}
		r, err := http.NewRequest(http.MethodPost, origin+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal("private device fixture request")
		}
		r.Host = "console.example.test"
		r.Header.Set("Content-Type", "application/json")
		if secret != "" {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("private device HTTP request failed; raw diagnostics suppressed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
		if err != nil || len(body) > protocol.MaxBodyBytes || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded or cacheable private device response")
		}
		if secret != "" && bytes.Contains(body, []byte(secret)) {
			t.Fatal("device credential entered a public response")
		}
		return response.StatusCode, body
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(token[:])
	fixtureSQL(t, binding, run, fmt.Sprintf(`BEGIN;
INSERT INTO public.tenants(id,name) VALUES('b1111111-1111-1111-1111-111111111111','Isolated HTTP enrollment fixture');
INSERT INTO public.users(id,tenant_id,email,role) VALUES('b2222222-2222-2222-2222-222222222222','b1111111-1111-1111-1111-111111111111','host@example.test','member');
INSERT INTO public.enroll_tokens(tenant_id,created_by_user_id,token_hash,created_at,expires_at) VALUES('b1111111-1111-1111-1111-111111111111','b2222222-2222-2222-2222-222222222222',decode('%x','hex'),clock_timestamp()-interval '1 minute',clock_timestamp()+interval '5 minutes');COMMIT`, digest[:]))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(publicDER)
	input := protocol.EnrollRequest{AgentProtocolVersion: protocol.Version, EnrollToken: base64.RawURLEncoding.EncodeToString(token[:]), Platform: "opnsense", PlatformVersion: "26.7.7", AgentVersion: "0.0.6", Capabilities: []string{"remote.web"}, Hostname: "isolated-client", GUIPublicKey: public}
	if err := input.Validate(); err != nil {
		t.Fatal("enrollment fixture omitted required protocol metadata")
	}
	status, body := post("/api/v1/devices/enroll", input, "")
	var enrolled protocol.EnrollResponse
	if status != 201 || json.Unmarshal(body, &enrolled) != nil || (protocol.Identity{AgentProtocolVersion: enrolled.AgentProtocolVersion, DeviceID: enrolled.DeviceID}).Validate() != nil || !protocol.ValidDeviceSecret(enrolled.DeviceSecret) {
		t.Fatal("genuine device enrollment failed", status)
	}
	bound, err := guicert.ValidatePublicKey(public)
	if err != nil || enrolled.GUIKeyFingerprint != bound.Fingerprint {
		t.Fatal("enrollment lost the client-held key")
	}
	authorized := func(action string, input any) (int, []byte) {
		path := "/api/v1/devices/gui-certificate/" + action
		if action == "unenroll" {
			path = "/api/v1/devices/unenroll"
		}
		return post(path, input, enrolled.DeviceSecret)
	}
	identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: enrolled.DeviceID}
	status, body = authorized("settings", identity)
	var settings protocol.CertificateSettings
	if status != 200 || json.Unmarshal(body, &settings) != nil || settings.Validate() != nil || settings.Request != nil || settings.AssignedHost != enrolled.Subdomain+".devices.example.test" || settings.GUIKeyFingerprint != bound.Fingerprint {
		t.Fatal("fresh device assignment readback failed", status)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{settings.AssignedHost}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.CertificateSubmit{Identity: identity, CSRDER: base64.StdEncoding.EncodeToString(der)}
	status, body = authorized("request", request)
	if status != 200 || json.Unmarshal(body, &settings) != nil || settings.Validate() != nil || settings.Request == nil || settings.Request.CSRDER != request.CSRDER {
		t.Fatal("authenticated original CSR admission and queue failed", status)
	}
	// The private CA uses Docker DNS for this newly assigned name. The original
	// fixed-name /etc/hosts entry remains only for older isolated fixture tests.
	proxy, network := "nethub-acme-test-"+nonce+"-proxy", "nethub-acme-test-"+nonce+"-network"
	if string(must(nil, "/usr/bin/docker", "inspect", "--format", `{{index .Config.Labels "org.nethub.guiacme-test"}}`, proxy)) != nonce {
		t.Fatal("fixture proxy ownership changed")
	}
	proxyAddress := string(must(nil, "/usr/bin/docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", proxy))
	if ip := net.ParseIP(proxyAddress); ip == nil || !ip.IsPrivate() || !strings.HasSuffix(settings.AssignedHost, ".devices.example.test") {
		t.Fatal("private challenge fixture address or assigned host invalid")
	}
	must(nil, "/usr/bin/docker", "network", "disconnect", network, proxy)
	must(nil, "/usr/bin/docker", "network", "connect", "--ip", proxyAddress, "--alias", settings.AssignedHost, network, proxy)
	return hostEnrolledDevice{settings: settings, csr: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), post: authorized}
}
