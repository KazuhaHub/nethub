package http01

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This opt-in genuine proxy test is executed by the isolated deployment harness.
func TestCaddyPublicHTTP01Route(t *testing.T) {
	image := os.Getenv("NETHUB_HTTP01_CADDY_IMAGE")
	if image == "" {
		t.Skip("requires the deployment harness's exact Caddy image")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("the isolated Docker acceptance harness requires Linux root")
	}
	p, value, now := fixture(t)
	if err := p.Publish(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	snippet, err := p.CaddyHTTPRoute("/challenges")
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	data, config := filepath.Join(stage, "data"), filepath.Join(stage, "config")
	for _, dir := range []string{data, config} {
		if os.Mkdir(dir, 0700) != nil || os.Chown(dir, 65532, 65532) != nil {
			t.Fatal("proxy storage fixture")
		}
	}
	console := "console1.routers.example.test"
	caddyfile := filepath.Join(stage, "Caddyfile")
	text := "{\n    admin off\n    skip_install_trust\n}\n" + console + " {\n    tls internal\n    respond console\n}\n" + snippet
	if os.WriteFile(caddyfile, []byte(text), 0644) != nil || os.Chmod(caddyfile, 0644) != nil {
		t.Fatal("proxy configuration fixture")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	operation := os.Getenv("NETHUB_HTTP01_TEST_NONCE")
	if operation == "" {
		operation = hex.EncodeToString(nonce[:])
	}
	if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(operation) {
		t.Fatal("invalid test operation identity")
	}
	name := "nethub-http01-test-" + operation
	network := name + "-network"
	command := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Log(string(out))
			t.Fatal("isolated proxy command failed")
		}
		return out
	}
	for _, target := range []struct{ kind, name string }{{"container", name}, {"network", network}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := exec.CommandContext(ctx, "docker", target.kind, "inspect", target.name).Run()
		cancel()
		if err == nil {
			t.Fatal("test operation identity already exists")
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		for _, target := range []struct{ kind, name string }{{"container", name}, {"network", network}} {
			out, err := exec.CommandContext(ctx, "docker", target.kind, "inspect", target.name).Output()
			var info []struct {
				ID     string
				Labels map[string]string
				Config struct{ Labels map[string]string }
			}
			if err != nil || json.Unmarshal(out, &info) != nil || len(info) != 1 {
				continue
			}
			labels := info[0].Labels
			if target.kind == "container" {
				labels = info[0].Config.Labels
			}
			if labels["org.nethub.http01-test"] != operation {
				t.Error("test resource ownership changed")
				continue
			}
			args := []string{target.kind, "rm"}
			if target.kind == "container" {
				args = append(args, "--force")
			}
			if err := exec.CommandContext(ctx, "docker", append(args, info[0].ID)...).Run(); err != nil {
				t.Error("owned test resource cleanup failed")
			}
		}
	})
	command("network", "create", "--internal", "--label", "org.nethub.http01-test="+operation, network)
	command("run", "--detach", "--name", name, "--pull", "never", "--network", network,
		"--label", "org.nethub.http01-test="+operation,
		"--user", "65532:65532", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
		"--mount", "type=bind,source="+p.public+",target=/challenges,readonly",
		"--mount", "type=bind,source="+caddyfile+",target=/etc/caddy/Caddyfile,readonly",
		"--mount", "type=bind,source="+data+",target=/data",
		"--mount", "type=bind,source="+config+",target=/config", image)
	var inspect []struct {
		ID         string
		Config     struct{ User string }
		State      struct{ Running bool }
		HostConfig struct {
			ReadonlyRootfs bool
			PortBindings   map[string]json.RawMessage
		}
		NetworkSettings struct {
			Ports    map[string][]struct{ HostIp, HostPort string }
			Networks map[string]struct{ IPAddress, NetworkID string }
		}
		Mounts []struct {
			Source, Destination string
			RW                  bool
		}
	}
	if json.Unmarshal(command("inspect", name), &inspect) != nil || len(inspect) != 1 {
		t.Fatal("proxy inspection unavailable")
	}
	info := inspect[0]
	if info.Config.User != "65532:65532" || !info.State.Running || !info.HostConfig.ReadonlyRootfs {
		t.Fatal("proxy lost its isolated role")
	}
	publicMounted := false
	for _, mount := range info.Mounts {
		if mount.Source == p.state || mount.Destination == "/challenges" && mount.RW {
			t.Fatal("proxy has private state or publication write access")
		}
		if mount.Destination == "/challenges" {
			publicMounted = mount.Source == p.public && !mount.RW
		}
	}
	if !publicMounted {
		t.Fatal("proxy publication directory binding changed")
	}
	if len(info.HostConfig.PortBindings) != 0 {
		t.Fatal("isolated proxy requested host port publication")
	}
	for _, bindings := range info.NetworkSettings.Ports {
		if len(bindings) != 0 {
			t.Fatal("isolated proxy published a host port")
		}
	}
	var networks []struct {
		ID         string
		Driver     string
		Internal   bool
		Containers map[string]json.RawMessage
	}
	if json.Unmarshal(command("network", "inspect", network), &networks) != nil || len(networks) != 1 || networks[0].Driver != "bridge" || !networks[0].Internal || len(info.NetworkSettings.Networks) != 1 {
		t.Fatal("proxy network is not the isolated test bridge")
	}
	attachment, ok := info.NetworkSettings.Networks[network]
	address, err := netip.ParseAddr(attachment.IPAddress)
	if !ok || err != nil || !address.Is4() || !address.IsPrivate() || attachment.NetworkID != networks[0].ID || networks[0].Containers[info.ID] == nil {
		t.Fatal("proxy address is not bound to the owned internal network")
	}
	// Internal bridges do not publish the requested host ports on the tested
	// engine. The Linux host can reach their private address directly; publish
	// no host ports and retain the network's external isolation instead.
	httpAddress, httpsAddress := net.JoinHostPort(address.String(), "80"), net.JoinHostPort(address.String(), "443")
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(func() { client.CloseIdleConnections() })
	request := func(host, path, method string) (int, string, string, error) {
		r, err := http.NewRequest(method, "http://"+httpAddress+path, nil)
		if err != nil {
			return 0, "", "", err
		}
		r.Host = host
		response, err := client.Do(r)
		if err != nil {
			return 0, "", "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		if response.StatusCode == 200 && (response.Header.Get("Content-Type") != "application/octet-stream" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff") {
			return 0, "", "", ErrState
		}
		return response.StatusCode, string(body), response.Header.Get("Location"), err
	}
	resource := "/.well-known/acme-challenge/" + value.Token
	deadline := time.Now().Add(25 * time.Second)
	for {
		status, body, _, err := request(value.Host, resource, "GET")
		if err == nil && status == 200 && body == value.KeyAuthorization {
			break
		}
		if time.Now().After(deadline) {
			t.Log(string(command("logs", name)))
			t.Fatal("actual Caddy did not serve the published response")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, test := range []struct{ host, path, method string }{
		{"z9y8x7w6.routers.example.test", resource, "GET"}, {"attacker.example.test", resource, "GET"},
		{value.Host, resource, "POST"}, {value.Host, resource + "?query=value", "GET"}, {value.Host, resource + "?", "GET"},
		{value.Host, "/.well-known/acme-challenge/" + strings.Repeat("B", 43), "GET"},
		{value.Host, "/.well-known/acme-challenge/%41" + value.Token[1:], "GET"},
		{value.Host, "/../.well-known/acme-challenge/" + value.Token, "GET"},
		{value.Host, "/.well-known/acme-challenge/../namespace.json", "GET"},
		{value.Host, "/.well-known/acme-challenge/", "GET"}, {value.Host, "/.publisher.json", "GET"},
	} {
		status, _, _, err := request(test.host, test.path, test.method)
		if err != nil || status != 404 {
			t.Fatalf("proxy did not reject an out-of-scope request: status=%d", status)
		}
	}
	if status, body, _, err := request(value.Host, resource, "HEAD"); err != nil || status != 200 || body != "" {
		t.Fatal("HEAD response invalid")
	}
	if status, _, location, err := request(console, "/console-path", "GET"); err != nil || status != 308 || location != "https://"+console+"/console-path" {
		t.Fatal("challenge routing overrode console redirect ownership")
	}
	rootFile := filepath.Join(data, "caddy/pki/authorities/local/root.crt")
	for missing(rootFile) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	rootPEM, err := os.ReadFile(rootFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("isolated console root unavailable")
	}
	tlsProbe := func(host string) error {
		dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}, NetDialer: &net.Dialer{Timeout: 3 * time.Second}}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		connection, err := dialer.DialContext(ctx, "tcp", httpsAddress)
		if err == nil {
			connection.Close()
		}
		return err
	}
	for {
		if err := tlsProbe(console); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("existing console TLS did not remain managed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := tlsProbe(value.Host); err == nil {
		t.Fatal("proxy acquired a GUI TLS identity")
	}
	writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	write := exec.CommandContext(writeCtx, "docker", "exec", name, "sh", "-c", "echo forbidden > /challenges/write-probe").Run()
	cancel()
	if write == nil || !missing(filepath.Join(p.public, "write-probe")) {
		t.Fatal("proxy wrote to issuer publication storage")
	}
	*now = value.ExpiresAt
	if err := p.CleanupExpired(context.Background(), value.Host); err != nil {
		t.Fatal(err)
	}
	if status, _, _, err := request(value.Host, resource, "GET"); err != nil || status != 404 {
		t.Fatal("retired file remained publicly served")
	}
	t.Log("Actual Caddy passed public response, cross-host/path/method rejection, read-only storage, cleanup and independent console TLS ownership")
}
