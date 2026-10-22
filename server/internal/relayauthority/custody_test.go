package relayauthority

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCustodyRequiresExplicitPhraseAndRechecksExactCopies(t *testing.T) {
	root, old, now := fixture(t)
	source, backup, path := filepath.Join(root, "candidate"), filepath.Join(root, "backup"), filepath.Join(root, "custody.json")
	if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err != nil {
		t.Fatal(err)
	}
	if Backup(source, backup, now) != nil {
		t.Fatal("backup fixture")
	}
	if _, err := AcknowledgeBackup(source, backup, path, "", now); err == nil {
		t.Fatal("implicit custody accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refused phrase wrote receipt")
	}
	first, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now.Add(time.Second))
	if err != nil || !retry.AcknowledgedAt.Equal(first.AcknowledgedAt) {
		t.Fatal("retry changed original acknowledgement")
	}
	if _, err := VerifyCustody(source, backup, path, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other-backup")
	if Backup(source, other, now) != nil {
		t.Fatal("second backup fixture")
	}
	if _, err := AcknowledgeBackup(source, other, path, CustodyPhrase, now); err == nil {
		t.Fatal("receipt rebound to different backup")
	}
	if os.WriteFile(filepath.Join(backup, "ca-key.pem"), []byte("damaged"), 0600) != nil {
		t.Fatal("damage fixture")
	}
	if _, err := VerifyCustody(source, backup, path, now); err == nil {
		t.Fatal("old receipt admitted damaged backup")
	}
	if _, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now); err == nil {
		t.Fatal("exact retry bypassed backup recheck")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("refused operation rewrote immutable receipt")
	}
}

func TestChangedCustodyReceiptCannotAuthorizeExistingCopies(t *testing.T) {
	for _, change := range []string{"metadata", "root", "path", "future", "before-preparation", "duplicate", "mode", "hardlink"} {
		t.Run(change, func(t *testing.T) {
			root, old, now := fixture(t)
			source, backup, path := filepath.Join(root, "candidate"), filepath.Join(root, "backup"), filepath.Join(root, "custody.json")
			if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err != nil {
				t.Fatal(err)
			}
			if Backup(source, backup, now) != nil {
				t.Fatal("fixture backup")
			}
			v, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "metadata":
				v.MetadataDigest = strings.Repeat("0", 64)
			case "root":
				v.Next = strings.Repeat("0", 64)
			case "path":
				v.Backup = source
			case "future":
				v.AcknowledgedAt = now.Add(time.Hour)
			case "before-preparation":
				v.AcknowledgedAt = now.Add(-time.Second)
			}
			raw, _ := json.Marshal(v)
			raw = append(raw, '\n')
			if change == "duplicate" {
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			}
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("fixture receipt")
			}
			if change == "mode" || change == "hardlink" {
				if runtime.GOOS == "windows" {
					t.Skip("POSIX protected receipt contract")
				}
				if change == "mode" {
					if os.Chmod(path, 0644) != nil {
						t.Fatal("fixture mode")
					}
				} else if os.Link(path, path+".alias") != nil {
					t.Fatal("fixture hardlink")
				}
			}
			if _, err := VerifyCustody(source, backup, path, now); err == nil {
				t.Fatal("changed receipt admitted")
			}
			if _, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now); err == nil {
				t.Fatal("exact retry replaced or ignored changed receipt")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, raw) {
				t.Fatal("refused receipt was rewritten")
			}
		})
	}
}

func TestCustodyRejectsUnknownAndOverlappingReceiptPaths(t *testing.T) {
	root, old, now := fixture(t)
	source, backup := filepath.Join(root, "candidate"), filepath.Join(root, "backup")
	if _, err := Prepare(source, "relay.example.test", old.CA, old.CAKey, now); err != nil {
		t.Fatal(err)
	}
	if Backup(source, backup, now) != nil {
		t.Fatal("fixture")
	}
	for _, path := range []string{filepath.Join(source, "custody.json"), filepath.Join(backup, "custody.json"), root} {
		if _, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now); err == nil {
			t.Fatal("overlapping receipt accepted")
		}
	}
	path := filepath.Join(root, "unknown.json")
	if os.WriteFile(path, []byte("unknown"), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := AcknowledgeBackup(source, backup, path, CustodyPhrase, now); err == nil {
		t.Fatal("unknown receipt overwritten")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "unknown" {
		t.Fatal("unknown bytes changed")
	}
}
