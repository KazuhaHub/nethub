package http01

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCleanupPolicyRequiresExistingNamespaceWithoutRepair(t *testing.T) {
	p, _, _ := fixture(t)
	path := filepath.Join(t.TempDir(), "http01.json")
	config := FileConfig{Version: 1, PublicDirectory: p.public, StateDirectory: p.state, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}}
	write := func() {
		data, _ := json.Marshal(config)
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("fixture config write")
		}
	}
	write()
	if _, err := OpenExistingFile(path); err != nil {
		t.Fatal("existing policy refused", err)
	}
	config.DeviceDomain = "unrelated.example.test"
	write()
	if _, err := OpenExistingFile(path); err == nil {
		t.Fatal("changed policy silently adopted")
	}
	config.DeviceDomain = p.domain
	write()
	lease := filepath.Join(p.public, ".publisher-lease")
	if os.Remove(lease) != nil {
		t.Fatal("fixture lease remove")
	}
	if _, err := OpenExistingFile(path); err == nil || !missing(lease) {
		t.Fatal("missing namespace lease recreated")
	}
	config.PublicDirectory = filepath.Join(t.TempDir(), "missing")
	write()
	if _, err := OpenExistingFile(path); err == nil || !missing(config.PublicDirectory) {
		t.Fatal("missing namespace initialized by cleanup")
	}
}

func TestCleanupPolicyRejectsUnknownDuplicateAndUnsafeFiles(t *testing.T) {
	p, _, _ := fixture(t)
	path := filepath.Join(t.TempDir(), "http01.json")
	config := FileConfig{Version: 1, PublicDirectory: p.public, StateDirectory: p.state, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}}
	valid, _ := json.Marshal(config)
	for _, data := range [][]byte{append(append([]byte{}, valid...), valid...), []byte(`{"version":1,"version":1}`), append(bytes.Clone(valid[:len(valid)-1]), []byte(`,"private_key":"must-not-be-accepted"}`)...)} {
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("fixture policy write")
		}
		if _, err := OpenExistingFile(path); err == nil {
			t.Fatal("ambiguous policy accepted")
		}
	}
	if os.WriteFile(path, valid, 0600) != nil {
		t.Fatal("fixture policy restore")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("fixture policy permissions")
	}
	if _, err := OpenExistingFile(path); err == nil {
		t.Fatal("readable policy accepted")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal("existing permissions repaired")
	}
}
