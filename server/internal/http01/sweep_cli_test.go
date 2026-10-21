package http01

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNativeHTTP01CleanupCLI(t *testing.T) {
	binary := os.Getenv("NETHUB_HTTP01_TEST_BINARY")
	if binary == "" {
		t.Skip("requires the separately built Linux host CLI")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("requires Linux root fixture")
	}
	p, value, now := fixture(t)
	*now = time.Now().UTC().Add(-20 * time.Minute)
	value.ExpiresAt = now.Add(time.Minute)
	if err := p.Publish(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	live := value
	live.Host = "b1b2c3d4.routers.example.test"
	live.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	*now = time.Now().UTC()
	if err := p.Publish(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	config := FileConfig{Version: 1, PublicDirectory: p.public, StateDirectory: p.state, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}}
	path := filepath.Join(t.TempDir(), "http01.json")
	data, _ := json.Marshal(config)
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fixture policy write")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "certificates", "cleanup-http01", "--config-file", path)
	output, err := command.Output()
	var result SweepResult
	if err != nil || json.Unmarshal(output, &result) != nil || result.Retired != 1 || result.Scanned != 2 || !result.CycleComplete {
		t.Fatal("real cleanup CLI did not retire only the expired proof")
	}
	expiredPath, _ := p.publicPath(value, false)
	livePath, _ := p.publicPath(live, false)
	if !missing(expiredPath) || missing(livePath) {
		t.Fatal("real CLI deleted live data or retained expired proof")
	}
	command = exec.CommandContext(ctx, binary, "certificates", "cleanup-http01", "--config-file", path)
	output, err = command.Output()
	if err != nil || json.Unmarshal(output, &result) != nil || result.Retired != 0 {
		t.Fatal("repeated cleanup not idempotent")
	}
	t.Log("Real Linux root cleanup CLI retired expired HTTP proof, preserved live proof and repeated idempotently without database/account dependencies")
}
