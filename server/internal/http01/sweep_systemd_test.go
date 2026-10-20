package http01

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeHTTP01CleanupTimer(t *testing.T) {
	nonce := os.Getenv("NETHUB_HTTP01_SYSTEMD_TEST_NONCE")
	if nonce == "" {
		t.Skip("requires the independently guarded Linux systemd fixture")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(nonce) {
		t.Fatal("invalid native cleanup fixture")
	}
	name := "nethub-http01-test-" + nonce
	public, private, configPath := filepath.Join("/srv", name), filepath.Join("/var/lib", name), filepath.Join("/etc", name+".json")
	for _, path := range []string{public, private, configPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("fixture path already exists")
		}
	}
	now := time.Now().UTC().Add(-20 * time.Minute)
	p, err := New(Config{PublicDirectory: public, StateDirectory: private, DeviceDomain: "routers.example.test", ExcludedHosts: []string{"console1.routers.example.test"}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	value := Publication{Host: "a1b2c3d4.routers.example.test", Generation: strings.Repeat("a", 32), Token: strings.Repeat("A", 43), KeyAuthorization: strings.Repeat("A", 43) + "." + strings.Repeat("A", 43), ExpiresAt: now.Add(time.Minute)}
	if err := p.Publish(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	now = time.Now().UTC()
	live := value
	live.Host = "b1b2c3d4.routers.example.test"
	live.ExpiresAt = now.Add(10 * time.Minute)
	if err := p.Publish(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(FileConfig{Version: 1, PublicDirectory: public, StateDirectory: private, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}})
	if os.WriteFile(configPath, data, 0600) != nil {
		t.Fatal("fixture policy write")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
		if err != nil {
			t.Fatal("fixture systemd operation failed; diagnostics retained privately")
		}
		return out
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		_ = exec.CommandContext(bounded, "systemctl", "stop", name+".timer", name+".service").Run()
	})
	command("start", name+".timer")
	expiredPath, _ := p.publicPath(value, false)
	livePath, _ := p.publicPath(live, false)
	for !missing(expiredPath) {
		if ctx.Err() != nil {
			t.Fatal("actual timer did not retire expired proof")
		}
		if strings.TrimSpace(string(command("show", name+".service", "--property=ActiveState", "--value"))) == "failed" {
			t.Fatal("actual cleanup unit failed before retiring proof")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for {
		state := strings.TrimSpace(string(command("show", name+".service", "--property=ActiveState", "--value")))
		if state == "inactive" {
			break
		}
		if state == "failed" || ctx.Err() != nil {
			t.Fatal("cleanup unit did not finish successfully")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if missing(livePath) {
		t.Fatal("actual timer deleted unexpired proof")
	}
	if strings.TrimSpace(string(command("show", name+".service", "--property=Result", "--value"))) != "success" {
		t.Fatal("cleanup service result failed")
	}
	for property, want := range map[string]string{"PrivateNetwork": "yes", "ProtectSystem": "strict", "NoNewPrivileges": "yes", "User": "root"} {
		if strings.TrimSpace(string(command("show", name+".service", "--property="+property, "--value"))) != want {
			t.Fatal("actual cleanup confinement missing")
		}
	}
	masked := string(command("show", name+".service", "--property=InaccessiblePaths", "--value"))
	if !strings.Contains(masked, "/run/docker.sock") || !strings.Contains(masked, "/run/postgresql") {
		t.Fatal("actual cleanup unit did not mask privileged sockets")
	}
	if strings.TrimSpace(string(command("show", name+".timer", "--property=ActiveState", "--value"))) != "active" {
		t.Fatal("independent timer not active")
	}
	if next := strings.TrimSpace(string(command("show", name+".timer", "--property=NextElapseUSecRealtime", "--value"))); next == "" || next == "n/a" || next == "0" {
		t.Fatal("independent timer has no following calendar activation")
	}
	t.Log("Actual shipped systemd cleanup timer/service ran with private networking and strict filesystem protection, retired expired proof, preserved live proof and exited successfully without database/account dependencies")
}
