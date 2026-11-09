package guiacme

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/http01"
)

func coldPrivateFile(path string, allowEmpty bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 || !allowEmpty && info.Size() == 0 {
		return nil, os.ErrPermission
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, os.ErrPermission
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if len(data) > 4096 {
		return nil, os.ErrPermission
	}
	return data, err
}

// The full driver must arm its independent nonce-owned cleanup guard before
// starting this opt-in process. No raw witness state is a public artifact.
func TestColdHostACMEWitness(t *testing.T) {
	control := os.Getenv("NETHUB_COLD_WITNESS_CONTROL")
	if control == "" {
		t.Skip("requires the guarded cold-host recovery driver")
	}
	nonce := os.Getenv("NETHUB_GUIACME_TEST_NONCE")
	parent, err := filepath.EvalSymlinks(os.Getenv("RUNNER_TEMP"))
	canonical, resolveErr := filepath.EvalSymlinks(control)
	info, statErr := os.Lstat(control)
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		err != nil || resolveErr != nil || statErr != nil || canonical != control || filepath.Dir(control) != parent ||
		!regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(nonce) || filepath.Base(control) != "nethub-cold-witness-"+nonce ||
		!info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("new private owned hosted witness control required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		t.Fatal("private witness control owner differs")
	}
	guard := "nethub-cold-witness-guard-" + nonce
	guardContext, guardCancel := context.WithTimeout(context.Background(), 5*time.Second)
	guardCommand := exec.CommandContext(guardContext, "/usr/bin/systemctl", "show", guard+".timer", "--property=ActiveState,Unit")
	guardCommand.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	guardOutput, guardErr := guardCommand.Output()
	guardCancel()
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(guardOutput)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || values[key] != "" {
			t.Fatal("independent witness cleanup guard state refused")
		}
		values[key] = value
	}
	if guardErr != nil || len(values) != 2 || values["ActiveState"] != "active" || values["Unit"] != guard+".service" {
		t.Fatal("active independent nonce-owned witness cleanup guard required")
	}
	raw, err := coldPrivateFile(filepath.Join(control, "request.json"), false)
	if err != nil {
		t.Fatal("private witness input unavailable")
	}
	request, err := decodeColdWitnessRequest(raw)
	if err != nil {
		t.Fatal("private witness input refused")
	}
	p := newPebbleHarnessForHost(t, request.Host, true, true)
	pebbleIssuingRoots(t, p)
	backup := filepath.Join(p.stage, "account-registered")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if p.store.Backup(ctx, backup) != nil || p.store.VerifyBackup(ctx, backup) != nil {
		t.Fatal("original registered private account snapshot unavailable")
	}
	publisher, err := http01.New(http01.Config{PublicDirectory: filepath.Join(p.stage, "route-public"),
		StateDirectory: filepath.Join(p.stage, "route-private"), DeviceDomain: "devices.example.test", ExcludedHosts: []string{"console.example.com"}})
	if err != nil {
		t.Fatal("private route renderer unavailable")
	}
	route, err := publisher.CaddyHTTPRoute("/nethub-http01")
	if err != nil {
		t.Fatal("stock HTTP-01 route rendering failed")
	}
	writeNew := func(name string, data []byte) {
		t.Helper()
		temporary := filepath.Join(control, "."+name+".prepared")
		file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("new private witness output unavailable")
		}
		_, writeErr := file.Write(data)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("private witness output failed")
		}
		if os.Link(temporary, filepath.Join(control, name)) != nil || os.Remove(temporary) != nil {
			t.Fatal("private witness atomic publication failed")
		}
		directory, err := os.Open(control)
		if err != nil {
			t.Fatal("private witness directory unavailable")
		}
		syncErr = directory.Sync()
		closeErr = directory.Close()
		if syncErr != nil || closeErr != nil {
			t.Fatal("private witness directory publication failed")
		}
	}
	writeNew("http01.caddy", []byte(route))
	gateway := p.address.Prev().String()
	listener, err := net.Listen("tcp4", net.JoinHostPort(gateway, "80"))
	if err != nil {
		t.Fatal("unused owned private validation listener required")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(gateway, strconv.Itoa(request.ForwardPort))}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(target)
		request.Out.Host = request.In.Host
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Unavailable", http.StatusBadGateway)
	}}
	var responses atomic.Uint64
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.StatusCode == 200 {
			responses.Add(1)
		}
		return nil
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second,
		MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, requestHTTP *http.Request) {
			if !coldWitnessAllowsHTTP(requestHTTP, p.address.String(), request.Host) {
				http.NotFound(w, requestHTTP)
				return
			}
			proxy.ServeHTTP(w, requestHTTP)
		})}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	t.Cleanup(func() { server.Close() })
	ready, err := json.Marshal(map[string]any{"version": 1, "host": request.Host,
		"directory_url": p.store.config.DirectoryURL, "contact_email": p.store.config.ContactEmail,
		"api_roots_file": filepath.Join(p.stage, "api-root.pem"), "certificate_roots_file": filepath.Join(p.stage, "issuing-root.pem"),
		"account_backup_directory": backup, "http01_route_file": filepath.Join(control, "http01.caddy"),
		"forward_address": gateway, "forward_port": request.ForwardPort})
	if err != nil {
		t.Fatal("private witness ready encoding failed")
	}
	writeNew("ready.json", ready)
	deadline := time.NewTimer(40 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("owned cold-host witness deadline exceeded")
		case <-serveResult:
			t.Fatal("owned cold-host validation listener stopped")
		case <-ticker.C:
			if _, err := coldPrivateFile(filepath.Join(control, "finish"), true); os.IsNotExist(err) {
				continue
			} else if err != nil {
				t.Fatal("private witness completion signal refused")
			}
			if responses.Load() == 0 {
				t.Fatal("no genuine CA-source HTTP-01 response crossed the guest forwarding path")
			}
			writeNew("witness-result.json", []byte(`{"actual_CA_source_HTTP01_response":true,"full_host_recovery_accepted":false}`+"\n"))
			return
		}
	}
}
