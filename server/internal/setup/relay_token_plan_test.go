package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

func tokenPlanFixture(t *testing.T) (string, string, Manifest, []byte, []byte) {
	t.Helper()
	root := t.TempDir()
	old := []byte(strings.Repeat("a", 64) + "\n")
	next := []byte(strings.Repeat("b", 64) + "\n")
	digest := sha256.Sum256(old)
	confirmed := time.Unix(1700000000, 0).UTC()
	m := Manifest{Version: 3, Config: Config{ConsoleHost: "console.example.com", DeviceDomain: "router.example.com", NetworkSubnet: "172.27.199.0/24", SourceDirectory: filepath.Join(root, "source"), OIDCPrivateHosts: []string{"idp.example.com"}}, BackupDirectory: filepath.Join(root, "previous-backup"), ConfirmedAt: &confirmed}
	for path, uid := range expectedOwners() {
		m.Files = append(m.Files, SecretFile{Path: path, SHA256: hex.EncodeToString(digest[:]), UID: uid, Size: 65})
	}
	return filepath.Join(root, "deployment"), filepath.Join(root, "successor-backup"), m, old, next
}

func TestRelayTokenManifestPreservesAuthorityAndOriginalInput(t *testing.T) {
	directory, successor, before, previous, candidate := tokenPlanFixture(t)
	original := before
	original.Files = append([]SecretFile(nil), before.Files...)
	after, err := relayTokenManifest(directory, successor, before, previous, candidate)
	if err != nil {
		t.Fatal("valid manifest plan refused", err)
	}
	expected := sha256.Sum256(candidate)
	changed := 0
	for i, file := range after.Files {
		if file.Path == "secrets/authz/frp_token" || file.Path == "secrets/frps/frp_token" {
			changed++
			if file.SHA256 != hex.EncodeToString(expected[:]) || file.UID != before.Files[i].UID || file.Size != before.Files[i].Size {
				t.Fatal("candidate/owner/size mismatch")
			}
		} else if file != before.Files[i] {
			t.Fatal("unrelated authority or credential changed")
		}
	}
	if changed != 2 || after.BackupDirectory != successor || !sameConfig(after.Config, before.Config) || *after.ConfirmedAt != *before.ConfirmedAt {
		t.Fatal("deployment identity changed")
	}
	if !reflect.DeepEqual(before, original) {
		t.Fatal("original snapshot mutated")
	}
	after.Files[0].SHA256 = "changed"
	after.Config.OIDCPrivateHosts[0] = "changed"
	*after.ConfirmedAt = time.Time{}
	if !reflect.DeepEqual(before, original) || before.Config.OIDCPrivateHosts[0] != "idp.example.com" || before.ConfirmedAt.IsZero() {
		t.Fatal("plan aliases original mutable input")
	}
	if !bytes.Equal(previous, []byte(strings.Repeat("a", 64)+"\n")) || !bytes.Equal(candidate, []byte(strings.Repeat("b", 64)+"\n")) {
		t.Fatal("input token mutated")
	}
}

func TestRelayTokenManifestRefusesAmbiguousPlans(t *testing.T) {
	for _, name := range []string{"unconfirmed", "legacy", "duplicate", "missing", "owner", "size", "digest", "old mismatch", "new same", "uppercase", "no newline", "backup reused", "backup nested", "deployment overlap", "relative", "invalid identity"} {
		t.Run(name, func(t *testing.T) {
			directory, successor, m, old, next := tokenPlanFixture(t)
			switch name {
			case "unconfirmed":
				m.ConfirmedAt = nil
			case "legacy":
				m.Version = 2
			case "duplicate":
				m.Files[1] = m.Files[0]
			case "missing":
				m.Files = m.Files[1:]
			case "owner":
				m.Files[0].UID = 1234
			case "size":
				m.Files[0].Size = 0
			case "digest":
				m.Files[0].SHA256 = "unknown"
			case "old mismatch":
				old = []byte(strings.Repeat("c", 64) + "\n")
			case "new same":
				next = old
			case "uppercase":
				next = []byte(strings.Repeat("B", 64) + "\n")
			case "no newline":
				next = next[:64]
			case "backup reused":
				successor = m.BackupDirectory
			case "backup nested":
				successor = filepath.Join(m.BackupDirectory, "new")
			case "deployment overlap":
				successor = filepath.Join(directory, "backup")
			case "relative":
				successor = "relative-backup"
			case "invalid identity":
				m.Config.ConsoleHost = m.Config.DeviceDomain
			}
			if _, err := relayTokenManifest(directory, successor, m, old, next); !errors.Is(err, relaytoken.ErrTransition) {
				t.Fatal("unsafe or changed original plan admitted")
			}
		})
	}
}
