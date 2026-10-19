package setup

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaymaint"
)

func TestHostMaintenanceRequiresExistingBoundContainer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux host adapter")
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if os.Mkdir(bin, 0700) != nil {
		t.Fatal("fixture bin")
	}
	metadata := filepath.Join(dir, "metadata.json")
	idFile := filepath.Join(dir, "container-id")
	id := strings.Repeat("a", 64)
	if os.WriteFile(idFile, []byte(id), 0600) != nil {
		t.Fatal("fixture id")
	}
	script := "#!/bin/sh\ncase \"$*\" in\n  *'ps --all --quiet frps'*) cat " + quote(idFile) + ";;\n  *mounts*) cat " + quote(metadata) + ";;\n  *com.docker.compose.project*) printf '%s\\n' 'fixture frps true';;\n  *) exit 19;;\nesac\n"
	if os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700) != nil {
		t.Fatal("fixture command")
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	host := relayHost{directory: dir, project: "fixture", args: []string{"compose"}}
	valid := map[string]any{"mounts": []map[string]any{
		{"Type": "bind", "Source": filepath.Join(dir, "secrets/frps"), "Destination": "/run/secrets", "RW": false},
		{"Type": "bind", "Source": filepath.Join(dir, "runtime/relay"), "Destination": "/run/relay", "RW": false}},
		"command": []string{"-c", "/run/secrets/frps.toml"}, "user": "65532:65532", "read_only": true, "network": "host"}
	write := func() {
		data, err := json.Marshal(valid)
		if err != nil || os.WriteFile(metadata, data, 0600) != nil {
			t.Fatal("fixture metadata")
		}
	}
	write()
	if running, err := host.Running(context.Background()); err != nil || !running {
		t.Fatal("matching protected service rejected")
	}
	valid["mounts"].([]map[string]any)[0]["Source"] = filepath.Join(dir, "another-deployment/secrets/frps")
	write()
	if _, err := host.Running(context.Background()); err != relaymaint.ErrState {
		t.Fatal("same project with another bundle's mounts accepted")
	}
	if os.WriteFile(idFile, nil, 0600) != nil {
		t.Fatal("fixture missing service")
	}
	if _, err := host.Running(context.Background()); err != relaymaint.ErrState {
		t.Fatal("unknown or deleted project treated as an existing stopped service")
	}
}

func TestMaintenanceCommandOutputRemainsBounded(t *testing.T) {
	var buffer commandBuffer
	n, err := io.Copy(&buffer, strings.NewReader(strings.Repeat("x", 100000)))
	if err != nil || n != 100000 || buffer.data.Len() != 65536 {
		t.Fatal("command output bypassed the fixed buffer limit")
	}
}
