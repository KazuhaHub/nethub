package guiacme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
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

// This digest is the Linux/amd64 image for official Pebble 2.10.1, release
// revision b1e1ca4f3c30abb64111adaca4544bc5374cc306. It is test-only.
const pebbleOrderImage = "ghcr.io/letsencrypt/pebble@sha256:5080492187bea12909c053d7a2b90a9e95104ef1c82381828e7823db71ce7e54"

type pebbleHarness struct {
	store                                    *AccountStore
	docker                                   func(...string) []byte
	network, name, nonce, stage, containerID string
	address                                  netip.Addr
	httpClient                               *http.Client
}

func newPebbleHarness(t *testing.T, management ...bool) *pebbleHarness {
	t.Helper()
	image := os.Getenv("NETHUB_GUIACME_PEBBLE_IMAGE")
	if image == "" {
		t.Skip("requires the isolated genuine ACME deployment harness")
	}
	if image != pebbleOrderImage || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("requires Linux root and the exact pinned test-only CA image")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	nonce := os.Getenv("NETHUB_GUIACME_TEST_NONCE")
	if nonce == "" {
		nonce = hex.EncodeToString(random[:])
	}
	if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(nonce) {
		t.Fatal("invalid test operation identity")
	}
	name := "nethub-acme-test-" + nonce
	network := name + "-network"
	label := "org.nethub.guiacme-test=" + nonce
	run := func(binary string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Log(string(out))
			t.Fatal("isolated ACME fixture command failed")
		}
		return out
	}
	docker := func(args ...string) []byte { return run("docker", args...) }
	for _, target := range []struct{ kind, name string }{{"container", name}, {"network", network}} {
		if exec.Command("docker", target.kind, "inspect", target.name).Run() == nil {
			t.Fatal("ACME test identity already exists")
		}
	}
	var used []netip.Prefix
	ids := strings.Fields(string(docker("network", "ls", "--quiet")))
	if len(ids) != 0 {
		var networks []struct {
			IPAM struct{ Config []struct{ Subnet string } }
		}
		if json.Unmarshal(docker(append([]string{"network", "inspect"}, ids...)...), &networks) != nil {
			t.Fatal("network inventory")
		}
		for _, n := range networks {
			for _, config := range n.IPAM.Config {
				if prefix, err := netip.ParsePrefix(config.Subnet); err == nil {
					used = append(used, prefix)
				}
			}
		}
	}
	var routes []struct{ Dst string }
	if json.Unmarshal(run("ip", "-4", "-j", "route", "show", "table", "all"), &routes) != nil {
		t.Fatal("host route inventory")
	}
	for _, route := range routes {
		if prefix, err := netip.ParsePrefix(route.Dst); err == nil && prefix.Bits() != 0 {
			used = append(used, prefix)
		} else if address, err := netip.ParseAddr(route.Dst); err == nil {
			used = append(used, netip.PrefixFrom(address, 32))
		}
	}
	var subnet netip.Prefix
	for octet := 100; octet < 250; octet++ {
		candidate := netip.MustParsePrefix(fmt.Sprintf("172.30.%d.0/24", octet))
		free := true
		for _, existing := range used {
			free = free && !candidate.Overlaps(existing)
		}
		if free {
			subnet = candidate
			break
		}
	}
	if !subnet.IsValid() {
		t.Fatal("no isolated nonoverlapping fixture subnet")
	}
	address := subnet.Addr().Next().Next()
	var containerID, networkID string
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if t.Failed() && containerID != "" {
			if logs, err := exec.CommandContext(ctx, "docker", "logs", containerID).CombinedOutput(); err == nil && !bytes.Contains(logs, []byte("PRIVATE KEY")) {
				t.Log(string(logs))
			}
		}
		for _, target := range []struct{ kind, id, name string }{{"container", containerID, name}, {"network", networkID, network}} {
			identity := target.id
			if identity == "" {
				identity = target.name
			}
			raw, err := exec.CommandContext(ctx, "docker", target.kind, "inspect", identity).Output()
			if err != nil {
				if target.id != "" {
					t.Error("owned ACME fixture inspection failed during cleanup")
				}
				continue
			}
			var info []struct {
				ID     string
				Labels map[string]string
				Config struct{ Labels map[string]string }
			}
			if json.Unmarshal(raw, &info) != nil || len(info) != 1 {
				t.Error("owned ACME fixture identity invalid")
				continue
			}
			labels := info[0].Labels
			if target.kind == "container" {
				labels = info[0].Config.Labels
			}
			if labels["org.nethub.guiacme-test"] != nonce {
				t.Error("ACME fixture ownership changed; resource preserved")
				continue
			}
			args := []string{target.kind, "rm"}
			if target.kind == "container" {
				args = append(args, "--force")
			}
			if exec.CommandContext(ctx, "docker", append(args, info[0].ID)...).Run() != nil {
				t.Error("owned ACME fixture cleanup failed")
			}
		}
	})
	networkID = strings.TrimSpace(string(docker("network", "create", "--internal", "--label", label, "--subnet", subnet.String(), network)))
	var networkInfo []struct {
		Internal bool
		Driver   string
		IPAM     struct{ Config []struct{ Subnet string } }
	}
	if json.Unmarshal(docker("network", "inspect", networkID), &networkInfo) != nil || len(networkInfo) != 1 ||
		!networkInfo[0].Internal || networkInfo[0].Driver != "bridge" || len(networkInfo[0].IPAM.Config) != 1 || networkInfo[0].IPAM.Config[0].Subnet != subnet.String() {
		t.Fatal("CA fixture network mismatch")
	}
	stage := t.TempDir()
	roots := pebbleAPIFixtureTLS(t, stage, net.ParseIP(address.String()))
	managementAddress := ""
	if len(management) == 1 && management[0] {
		managementAddress = "0.0.0.0:15000"
	}
	configuration := map[string]any{"pebble": map[string]any{
		"listenAddress": "0.0.0.0:14000", "managementListenAddress": managementAddress, "certificate": "/fixture/cert.pem", "privateKey": "/fixture/key.pem",
		"httpPort": 80, "tlsPort": 5001, "externalAccountBindingRequired": false,
		"profiles": map[string]any{"standard": map[string]any{"description": "isolated order test", "validityPeriod": 7776000}},
	}}
	raw, _ := json.Marshal(configuration)
	if os.WriteFile(filepath.Join(stage, "config.json"), raw, 0600) != nil {
		t.Fatal("CA configuration fixture")
	}
	containerID = strings.TrimSpace(string(docker("create", "--name", name, "--label", label, "--network", network,
		"--ip", address.String(), "--read-only", "--user", "0:0", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m",
		"--add-host", orderHost+":"+address.Next().String(), "--env", "PEBBLE_VA_NOSLEEP=1",
		"--env", "PEBBLE_WFE_NONCEREJECT=0", "--env", "PEBBLE_AUTHZREUSE=0",
		"--mount", "type=bind,src="+filepath.Join(stage, "cert.pem")+",dst=/fixture/cert.pem,readonly",
		"--mount", "type=bind,src="+filepath.Join(stage, "key.pem")+",dst=/fixture/key.pem,readonly",
		"--mount", "type=bind,src="+filepath.Join(stage, "config.json")+",dst=/fixture/config.json,readonly",
		image, "-config", "/fixture/config.json", "-strict=false")))
	docker("start", containerID)
	var loaded []struct{ ID string }
	if json.Unmarshal(docker("image", "inspect", image), &loaded) != nil || len(loaded) != 1 {
		t.Fatal("pinned fixture image identity")
	}
	var info []struct {
		Image string
		State struct {
			Running  bool
			ExitCode int
		}
		HostConfig struct {
			ReadonlyRootfs bool
			PortBindings   map[string]any
		}
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if json.Unmarshal(docker("inspect", containerID), &info) != nil || len(info) != 1 ||
		info[0].Image != loaded[0].ID || !info[0].HostConfig.ReadonlyRootfs || len(info[0].HostConfig.PortBindings) != 0 ||
		len(info[0].NetworkSettings.Networks) != 1 || info[0].NetworkSettings.Networks[network].IPAddress != address.String() {
		if len(info) == 1 {
			t.Logf("fixture image match=%t readonly=%t port bindings=%d networks=%d address match=%t running=%t exit=%d",
				info[0].Image == loaded[0].ID, info[0].HostConfig.ReadonlyRootfs, len(info[0].HostConfig.PortBindings),
				len(info[0].NetworkSettings.Networks), info[0].NetworkSettings.Networks[network].IPAddress == address.String(), info[0].State.Running, info[0].State.ExitCode)
			t.Log(string(docker("logs", containerID)))
		}
		t.Fatal("CA fixture isolation mismatch")
	}
	origin := "https://" + net.JoinHostPort(address.String(), "14000")
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRemote }}
	deadline := time.Now().Add(15 * time.Second)
	var terms string
	for {
		response, err := httpClient.Get(origin + "/dir")
		if err == nil {
			var directory struct {
				Meta struct {
					Terms string `json:"termsOfService"`
				}
			}
			err = json.NewDecoder(response.Body).Decode(&directory)
			response.Body.Close()
			if err == nil && response.StatusCode == 200 {
				terms = directory.Meta.Terms
				break
			}
		}
		if time.Now().After(deadline) {
			t.Log(string(docker("logs", containerID)))
			if err != nil {
				t.Logf("private readiness failure: %v", err)
			}
			t.Fatal("private CA did not become ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	store, err := NewAccountStore(filepath.Join(stage, "account"), Config{DirectoryURL: origin + "/dir", Roots: roots, ContactEmail: "admin@example.test"})
	if err != nil || store.Initialize(context.Background()) != nil {
		t.Fatal("private test account initialization")
	}
	if _, err := store.EnsureAccount(context.Background(), false, ""); err != ErrConsent {
		t.Fatalf("implicit test account registration: %v", err)
	}
	if _, err := store.EnsureAccount(context.Background(), true, terms); err != nil {
		t.Fatalf("explicit isolated CA account registration: %v", err)
	}
	return &pebbleHarness{store: store, docker: docker, network: network, name: name, nonce: nonce, stage: stage, containerID: containerID, address: address, httpClient: httpClient}
}

func TestPebbleOrderAdmission(t *testing.T) {
	harness := newPebbleHarness(t)
	store, docker, containerID := harness.store, harness.docker, harness.containerID
	before, _ := os.ReadFile(store.path("account.json"))
	csr, public := orderRequest(t)
	order, err := store.CreateOrder(context.Background(), csr, orderHost, public)
	if err != nil || order.Status != "pending" || order.Profile != "standard" {
		t.Fatalf("genuine CA bound order: %v", err)
	}
	for range 3 {
		observed, err := store.InspectOrder(context.Background(), order.URI, csr, orderHost, public)
		if err != nil || observed != order {
			t.Fatalf("genuine CA saved-order observation: %v", err)
		}
	}
	after, _ := os.ReadFile(store.path("account.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("genuine CA order replaced persisted account state")
	}
	logs := docker("logs", containerID)
	if bytes.Contains(logs, []byte("PRIVATE KEY")) || !bytes.Contains(logs, []byte("There are now 1 orders in the db")) || bytes.Contains(logs, []byte("There are now 2 orders in the db")) {
		t.Fatal("genuine CA order count or key-log boundary failed")
	}
	t.Log("Actual Pebble passed explicit account consent, bound single-name order, advertised default profile and same-order recovery; no challenge accepted or certificate issued")
}

func pebbleAPIFixtureTLS(t *testing.T, stage string, address net.IP) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated ACME API fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: root.NotBefore, NotAfter: root.NotAfter,
		IPAddresses: []net.IP{address}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	apiKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &apiKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(apiKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{
		"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"key.pem":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
	} {
		if os.WriteFile(filepath.Join(stage, name), value, 0600) != nil {
			t.Fatal("isolated API TLS fixture")
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	return roots
}
