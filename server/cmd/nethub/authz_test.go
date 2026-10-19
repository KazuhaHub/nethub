package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuthzFlagsAndMaterial(t *testing.T) {
	for _, args := range [][]string{{"authz"}, {"authz", "--port", "70000"}, {"authz", "--relay-port", "0"},
		{"authz", "--trusted-proxy", "invalid"}, {"authz", "unexpected"}} {
		var out, diagnostic bytes.Buffer
		if status := run(args, &out, &diagnostic); status != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
			t.Fatalf("invalid authz flags: status=%d", status)
		}
	}
	var out, diagnostic bytes.Buffer
	if status := run([]string{"authz", "--help"}, &out, &diagnostic); status != 0 || diagnostic.Len() == 0 {
		t.Fatal("authz help failed")
	}
	path := filepath.Join(t.TempDir(), "claim_key")
	value := strings.Repeat("ab", 32)
	if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	decoded, err := readAuthzHex(path)
	if err != nil || len(decoded) != 32 || decoded[0] != 0xab {
		t.Fatal("deployment hex key was not decoded into 32 raw signing bytes")
	}
	for _, invalid := range []string{"", strings.ToUpper(value), value + "00", "private-invalid-material", strings.Repeat("x", 129)} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readAuthzHex(path); err == nil || strings.Contains(err.Error(), invalid) && invalid != "" {
			t.Fatal("invalid key accepted or included in diagnostics")
		}
	}
	if _, err := readAuthzFile(filepath.Dir(path), 128, true); err == nil {
		t.Fatal("directory accepted as key material")
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readAuthzHex(path); err == nil {
			t.Fatal("group/world-readable signing key accepted")
		}
		link := path + ".link"
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readAuthzHex(link); err == nil {
			t.Fatal("linked signing key accepted")
		}
	}
}
