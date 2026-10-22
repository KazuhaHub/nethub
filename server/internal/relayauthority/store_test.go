package relayauthority

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

func fixture(t *testing.T) (string, relaycert.Material, time.Time) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private fixture")
	}
	now := time.Now().UTC().Truncate(time.Second)
	old, err := relaycert.Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	return root, old, now
}

func TestPrepareAndIndependentBackupPreserveBoundIdentity(t *testing.T) {
	root, old, now := fixture(t)
	source := filepath.Join(root, "candidate")
	beforeCA, beforeKey := bytes.Clone(old.CA), bytes.Clone(old.CAKey)
	c, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Metadata.Previous == c.Metadata.Next || c.Metadata.ServerName != "relay.example.test" {
		t.Fatal("candidate binding")
	}
	encoded, err := json.Marshal(c)
	if err != nil || bytes.Contains(encoded, []byte("PRIVATE")) || bytes.Contains(encoded, []byte("BEGIN")) {
		t.Fatal("candidate serialized key or PEM")
	}
	backup := filepath.Join(root, "backup")
	if Backup(source, backup, now) != nil || VerifyBackup(source, backup, now) != nil {
		t.Fatal("independent backup refused")
	}
	for _, name := range append(append([]string{}, names...), "candidate.json") {
		a, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(backup, name))
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("backup bytes differ")
		}
	}
	if !bytes.Equal(old.CA, beforeCA) || !bytes.Equal(old.CAKey, beforeKey) {
		t.Fatal("original authority changed")
	}
	if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err == nil {
		t.Fatal("existing candidate replaced")
	}
	if Backup(source, backup, now) == nil {
		t.Fatal("existing backup replaced")
	}
	loaded, err := Load(source, now)
	if err != nil || loaded.Metadata.Next != c.Metadata.Next {
		t.Fatal("candidate changed after refused writes")
	}
	if _, err := Load(source, now.AddDate(2, 0, 0)); err == nil {
		t.Fatal("expired candidate leaf accepted for activation planning")
	}
}

func TestPartialAndUnexpectedCandidateCannotBeBlessed(t *testing.T) {
	for _, change := range []string{"missing", "corrupt-key", "unknown-file", "metadata", "duplicate-json", "private-mode", "link"} {
		t.Run(change, func(t *testing.T) {
			root, old, now := fixture(t)
			source := filepath.Join(root, "candidate")
			if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(source, "ca-key.pem")
			metadata := filepath.Join(source, "candidate.json")
			switch change {
			case "missing":
				if os.Remove(metadata) != nil {
					t.Fatal("remove fixture")
				}
			case "corrupt-key":
				if os.WriteFile(key, []byte("not a key"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "unknown-file":
				if os.WriteFile(filepath.Join(source, "unexpected"), []byte("x"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "metadata":
				raw, _ := os.ReadFile(metadata)
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1)
				if os.WriteFile(metadata, raw, 0600) != nil {
					t.Fatal("fixture")
				}
			case "duplicate-json":
				raw, _ := os.ReadFile(metadata)
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
				if os.WriteFile(metadata, raw, 0600) != nil {
					t.Fatal("fixture")
				}
			case "private-mode":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX ownership contract")
				}
				if os.Chmod(key, 0644) != nil {
					t.Fatal("fixture")
				}
			case "link":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX single-link contract")
				}
				if os.Link(key, filepath.Join(root, "alias")) != nil {
					t.Fatal("fixture")
				}
			}
			if _, err := Load(source, now); err == nil {
				t.Fatal("partial or unsafe candidate loaded")
			}
			if Backup(source, filepath.Join(root, "backup"), now) == nil {
				t.Fatal("unsafe candidate backed up")
			}
			if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err == nil {
				t.Fatal("partial state overwritten")
			}
		})
	}
}

func TestBackupAliasesAndNestingCannotSatisfyCustody(t *testing.T) {
	root, old, now := fixture(t)
	source := filepath.Join(root, "candidate")
	if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source, filepath.Join(source, "nested"), root} {
		if Backup(source, path, now) == nil || VerifyBackup(source, path, now) == nil {
			t.Fatal("overlapping backup admitted")
		}
	}
	backup := filepath.Join(root, "backup")
	if Backup(source, backup, now) != nil {
		t.Fatal("fixture backup")
	}
	target := filepath.Join(backup, "ca-key.pem")
	if os.Remove(target) != nil || os.Link(filepath.Join(source, "ca-key.pem"), target) != nil {
		t.Fatal("alias fixture")
	}
	if VerifyBackup(source, backup, now) == nil {
		t.Fatal("same-inode backup admitted")
	}
	if _, err := Load(source, now); runtime.GOOS != "windows" && err == nil {
		t.Fatal("aliased source key not refused")
	}
}

func TestWrongOldKeyAndLinkedDestinationDoNotCreateCandidate(t *testing.T) {
	root, old, now := fixture(t)
	other, err := relaycert.Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "candidate")
	if _, err := Prepare(path, "relay.example.test", old.CA, other.CAKey, now); err == nil {
		t.Fatal("unrelated old key accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("invalid input left output")
	}
	linked := filepath.Join(root, "linked")
	if os.Symlink(root, linked) != nil {
		t.Skip("symlink fixture unavailable")
	}
	if _, err := Prepare(filepath.Join(linked, "candidate"), "relay.example.test", old.CA, old.CAKey, now); err == nil {
		t.Fatal("linked output parent accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("linked parent changed outside target")
	}
}

func TestExpiredOriginalAuthorityCanBeIdentifiedWithoutActivatingSuccessor(t *testing.T) {
	root, old, now := fixture(t)
	later := now.AddDate(11, 0, 0)
	c, err := Prepare(filepath.Join(root, "successor"), "relay.example.test", old.CA, old.CAKey, later)
	if err != nil {
		t.Fatal("expired original identity prevented offline preparation", err)
	}
	id, err := relaycert.AuthorityIdentity(old.CA, old.CAKey)
	if err != nil || c.Metadata.Previous != id {
		t.Fatal("expired original binding was lost")
	}
	if relaycert.Check(old.CA, old.Certificate, old.Key, "relay.example.test", later) == nil {
		t.Fatal("expired original unexpectedly valid")
	}
	if relaycert.Check(c.Material.CA, c.Material.Certificate, c.Material.Key, "relay.example.test", later) != nil {
		t.Fatal("new successor not independently valid")
	}
}
