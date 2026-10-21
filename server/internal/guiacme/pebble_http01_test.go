package guiacme

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/http01"
)

func TestPebbleHTTP01Validation(t *testing.T) {
	if os.Getenv("NETHUB_GUIACME_PEBBLE_IMAGE") == "" {
		t.Skip("requires the isolated genuine ACME deployment harness")
	}
	image := os.Getenv("NETHUB_GUIACME_CADDY_IMAGE")
	if image == "" {
		t.Fatal("requires the exact deployment Caddy image")
	}
	p := newPebbleHarness(t)
	name := p.name + "-proxy"
	if exec.Command("docker", "container", "inspect", name).Run() == nil {
		t.Fatal("proxy fixture identity already exists")
	}
	pub, private := filepath.Join(p.stage, "http-public"), filepath.Join(p.stage, "http-private")
	publisher, err := http01.New(http01.Config{PublicDirectory: pub, StateDirectory: private, DeviceDomain: "devices.example.test"})
	if err != nil {
		t.Fatal("isolated publisher initialization")
	}
	snippet, err := publisher.CaddyHTTPRoute("/challenges")
	if err != nil {
		t.Fatal(err)
	}
	snippet = strings.Replace(snippet, ":80 {\n", ":80 {\n    log {\n        output stdout\n        format json\n    }\n", 1)
	configuration := "{\n    admin off\n    auto_https off\n}\n" + snippet
	file := filepath.Join(p.stage, "Caddyfile")
	if os.WriteFile(file, []byte(configuration), 0644) != nil || os.Chmod(file, 0644) != nil {
		t.Fatal("proxy configuration fixture")
	}
	for _, name := range []string{"proxy-data", "proxy-config"} {
		path := filepath.Join(p.stage, name)
		if os.Mkdir(path, 0700) != nil || os.Chown(path, 65532, 65532) != nil {
			t.Fatal("proxy scratch fixture")
		}
	}
	var cid string
	t.Cleanup(func() {
		identity := cid
		if identity == "" {
			identity = name
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		raw, err := exec.CommandContext(ctx, "docker", "inspect", identity).Output()
		if err != nil {
			if cid != "" {
				t.Error("owned proxy inspection failed")
			}
			return
		}
		var values []struct {
			ID     string
			Config struct{ Labels map[string]string }
		}
		if json.Unmarshal(raw, &values) != nil || len(values) != 1 || values[0].Config.Labels["org.nethub.guiacme-test"] != p.nonce {
			t.Error("proxy ownership changed; resource preserved")
			return
		}
		if exec.CommandContext(ctx, "docker", "rm", "--force", values[0].ID).Run() != nil {
			t.Error("owned proxy removal failed")
		}
	})
	cid = strings.TrimSpace(string(p.docker("create", "--name", name, "--label", "org.nethub.guiacme-test="+p.nonce,
		"--network", p.network, "--ip", p.address.Next().String(), "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
		"--mount", "type=bind,src="+pub+",dst=/challenges,readonly",
		"--mount", "type=bind,src="+file+",dst=/etc/caddy/Caddyfile,readonly",
		"--mount", "type=bind,src="+filepath.Join(p.stage, "proxy-data")+",dst=/data",
		"--mount", "type=bind,src="+filepath.Join(p.stage, "proxy-config")+",dst=/config",
		image, "caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")))
	p.docker("start", cid)
	var info []struct {
		Config     struct{ User string }
		HostConfig struct {
			ReadonlyRootfs bool
			PortBindings   map[string]any
		}
		Mounts []struct {
			Source, Destination string
			RW                  bool
		}
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if json.Unmarshal(p.docker("inspect", cid), &info) != nil || len(info) != 1 || info[0].Config.User != "65532:65532" ||
		!info[0].HostConfig.ReadonlyRootfs || len(info[0].HostConfig.PortBindings) != 0 || len(info[0].NetworkSettings.Networks) != 1 ||
		info[0].NetworkSettings.Networks[p.network].IPAddress != p.address.Next().String() || len(info[0].Mounts) != 4 {
		t.Fatal("HTTP-01 proxy isolation mismatch")
	}
	for _, m := range info[0].Mounts {
		switch m.Destination {
		case "/challenges":
			if m.Source != pub || m.RW {
				t.Fatal("public-only challenge mount")
			}
		case "/etc/caddy/Caddyfile":
			if m.Source != file || m.RW {
				t.Fatal("read-only route fixture")
			}
		case "/data":
			if m.Source != filepath.Join(p.stage, "proxy-data") {
				t.Fatal("proxy data fixture")
			}
		case "/config":
			if m.Source != filepath.Join(p.stage, "proxy-config") {
				t.Fatal("proxy config fixture")
			}
		default:
			t.Fatal("unexpected proxy mount")
		}
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRemote }}
	fetch := func(host, path string) (int, string, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(p.address.Next().String(), "80")+path, nil)
		if err != nil {
			return 0, "", err
		}
		req.Host = host
		response, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, string(body), err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, _, err := fetch(orderHost, "/")
		if err == nil && status == 404 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP-only proxy did not become ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	csr, public := orderRequest(t)
	order, err := p.store.CreateOrder(context.Background(), csr, orderHost, public)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := p.store.PrepareHTTP01(context.Background(), order, csr, public)
	if err != nil || challenge.Complete {
		t.Fatalf("genuine challenge preparation: %v", err)
	}
	path := "/.well-known/acme-challenge/" + challenge.Token
	if status, _, err := fetch(orderHost, path); err != nil || status != 404 {
		t.Fatal("unpublished challenge was served")
	}
	challenge.ExpiresAt = time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	publication := http01.Publication{Host: order.Host, Generation: strings.Repeat(p.nonce, 2), Token: challenge.Token, KeyAuthorization: challenge.KeyAuthorization, ExpiresAt: challenge.ExpiresAt}
	if err := publisher.Publish(context.Background(), publication); err != nil {
		t.Fatalf("durable challenge publication: %v", err)
	}
	if status, body, err := fetch(orderHost, path); err != nil || status != 200 || body != challenge.KeyAuthorization {
		t.Fatal("exact published response unavailable")
	}
	if status, _, err := fetch("ijklmnop.devices.example.test", path); err != nil || status != 404 {
		t.Fatal("cross-host challenge served")
	}
	if _, err := p.store.AcceptHTTP01(context.Background(), challenge, csr, public); err != nil {
		t.Fatalf("genuine challenge acceptance: %v", err)
	}
	deadline = time.Now().Add(25 * time.Second)
	for {
		current, err := p.store.InspectOrder(context.Background(), order.URI, csr, orderHost, public)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == "ready" {
			break
		}
		if current.Status != "pending" || time.Now().After(deadline) {
			t.Fatal("CA did not validate the published HTTP response")
		}
		time.Sleep(100 * time.Millisecond)
	}
	completed, err := p.store.AcceptHTTP01(context.Background(), challenge, csr, public)
	if err != nil || !completed.Complete {
		t.Fatalf("validated challenge recovery: %v", err)
	}
	if err := publisher.Remove(context.Background(), order.Host, publication.Generation); err != nil {
		t.Fatal(err)
	}
	if status, _, err := fetch(orderHost, path); err != nil || status != 404 {
		t.Fatal("retired HTTP response remains available")
	}
	matched := false
	for _, line := range strings.Split(string(p.docker("logs", cid)), "\n") {
		var entry struct {
			Status  int
			Request struct {
				RemoteIP  string `json:"remote_ip"`
				Host, URI string
			}
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Status == 200 && entry.Request.URI == path {
			host := entry.Request.Host
			if value, port, err := net.SplitHostPort(host); err == nil && port == "80" {
				host = value
			}
			if entry.Request.RemoteIP == p.address.String() && host == orderHost {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("no independent successful CA fetch in proxy access log")
	}
	t.Log("Actual Pebble HTTP-01 validation passed durable publisher, genuine Caddy response, CA-source fetch, same-order ready recovery and retired response removal; no certificate finalized")
}
