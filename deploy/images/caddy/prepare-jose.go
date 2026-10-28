//go:build ignore

// Prepare a private vendored build with pinned downstream JOSE API adaptations.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if err := prepare(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prepare() error {
	if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) || filepath.Clean(os.Args[1]) != os.Args[1] {
		return fmt.Errorf("usage: go run prepare-jose.go NEW_ABSOLUTE_OUTPUT_DIRECTORY")
	}
	raw, err := exec.Command("go", "list", "-m", "-json", "github.com/smallstep/certificates").Output()
	if err != nil {
		return fmt.Errorf("cannot inspect pinned Smallstep module")
	}
	var module struct {
		Path, Version, Dir string
		Replace            json.RawMessage
	}
	if json.Unmarshal(raw, &module) != nil || module.Path != "github.com/smallstep/certificates" || module.Version != "v0.30.2" || module.Dir == "" || len(module.Replace) != 0 {
		return fmt.Errorf("Smallstep module identity changed; review the compatibility migration")
	}
	type adaptation struct{ name, digest, before, after string }
	changes := []adaptation{
		{"aws.go", "44555f3094cff9ad088f6f47bf70bdd2718146cb40382a5f6caef9fe154d8e69", ".Claims(payload).CompactSerialize()", ".Claims(payload).Serialize()"},
		{"azure.go", "200f4f9fc40dc79dfacfb8e5411ebc7fb2b894c8d2bd8a300088b455b918bbeb", "Audience: []string{p.Audience}", "AnyAudience: []string{p.Audience}"},
		{"oidc.go", "830a70c021c1058f6a5bf00ec3a128b883cdf1bf36338f163670ae629844b5b2", "Audience: jose.Audience{o.ClientID}", "AnyAudience: jose.Audience{o.ClientID}"},
	}
	prepared := map[string][]byte{}
	originals := map[string][]byte{}
	for _, change := range changes {
		path := filepath.Join(module.Dir, "authority", "provisioner", change.name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read pinned compatibility input: %s", change.name)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != change.digest || strings.Count(string(data), change.before) != 1 {
			return fmt.Errorf("compatibility input changed: %s; review before rebuilding", change.name)
		}
		prepared[change.name] = []byte(strings.Replace(string(data), change.before, change.after, 1))
		originals[change.name] = data
	}
	if err := os.Mkdir(os.Args[1], 0700); err != nil {
		return fmt.Errorf("compatibility output directory must be new")
	}
	for _, name := range []string{"go.mod", "go.sum", "main.go", "jose_test.go"} {
		data, err := os.ReadFile(name)
		if err != nil || os.WriteFile(filepath.Join(os.Args[1], name), data, 0600) != nil {
			return fmt.Errorf("cannot copy helper build input: %s", name)
		}
	}
	vendor := filepath.Join(os.Args[1], "vendor")
	command := exec.Command("go", "mod", "vendor", "-o", vendor)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Run() != nil {
		return fmt.Errorf("cannot prepare checksum-pinned vendored dependencies")
	}
	for name, data := range prepared {
		destination := filepath.Join(vendor, "github.com", "smallstep", "certificates", "authority", "provisioner", name)
		original, err := os.ReadFile(destination)
		if err != nil || string(original) != string(originals[name]) {
			return fmt.Errorf("vendored compatibility input changed: %s", name)
		}
		if err := os.WriteFile(destination, data, 0600); err != nil {
			return fmt.Errorf("cannot write vendored compatibility input: %s", name)
		}
	}
	return nil
}
