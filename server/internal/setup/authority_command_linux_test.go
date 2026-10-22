package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

func commandRecordFixture(t *testing.T) authorityCommandRecord {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private fixture")
	}
	return authorityCommandRecord{Version: 1, Project: "nethub", Options: RelayAuthoritySnapshotOptions{
		Directory: root, CandidateDirectory: "/root/candidate", CandidateBackup: "/root/candidate-backup",
		CustodyFile: "/root/custody.json", SuccessorBackup: "/root/successor-backup", ServiceFingerprint: strings.Repeat("a", 64),
		Request: relaytrust.SwitchRequest{ID: "01234567-89ab-4cde-8123-456789abcdef", GenerationID: "01234567-89ab-4cde-8123-456789abcdee",
			PreviousRoot: strings.Repeat("b", 64), NextRoot: strings.Repeat("c", 64), PreviousLeaf: strings.Repeat("d", 64), NextLeaf: strings.Repeat("e", 64)},
	}}
}

func TestAuthorityCommandRejectsAmbiguousOriginalInput(t *testing.T) {
	record := commandRecordFixture(t)
	raw := authorityJSON(record.Options)
	if _, err := decodeAuthorityCommandOptions(raw); err != nil {
		t.Fatal("valid explicit original options refused", err)
	}
	for _, bad := range [][]byte{
		[]byte("null"), append(bytes.Clone(raw[:len(raw)-2]), []byte(",\"unexpected\":true}\n")...),
		bytes.Replace(raw, []byte(`"previous_root":`), []byte(`"id":"duplicate","previous_root":`), 1),
		bytes.Replace(raw, []byte(`"candidate":"/root/candidate"`), []byte(`"candidate":"relative"`), 1),
		bytes.Replace(raw, []byte(record.Options.ServiceFingerprint), []byte(""), 1),
	} {
		if _, err := decodeAuthorityCommandOptions(bad); err == nil {
			t.Fatal("ambiguous or incomplete activation input admitted")
		}
	}
}

func TestAuthorityCommandRetainsOriginalBeforeAnySnapshot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires the actual Linux root-owned record contract")
	}
	record := commandRecordFixture(t)
	if retainAuthorityCommand(record) != nil || retainAuthorityCommand(record) != nil {
		t.Fatal("original record and exact retry")
	}
	path := filepath.Join(record.Options.Directory, "authority-commands", record.Options.Request.ID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := record
	changed.Options.ServiceFingerprint = strings.Repeat("f", 64)
	if retainAuthorityCommand(changed) == nil {
		t.Fatal("changed original binding replaced the operation")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retained input changed")
	}
	loaded, err := readAuthorityCommand(record.Options.Directory, record.Options.Request.ID)
	if err != nil || loaded != record {
		t.Fatal("original input unavailable without snapshot", err)
	}
	if _, err := os.Lstat(filepath.Join(record.Options.Directory, "authority-transitions")); !os.IsNotExist(err) {
		t.Fatal("retention created a transition or snapshot")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("mode fixture")
	}
	if _, err := readAuthorityCommand(record.Options.Directory, record.Options.Request.ID); err == nil {
		t.Fatal("public original input admitted")
	}
	if os.Chmod(path, 0600) != nil || os.Link(path, path+".alias") != nil {
		t.Fatal("hardlink fixture")
	}
	if _, err := readAuthorityCommand(record.Options.Directory, record.Options.Request.ID); err == nil {
		t.Fatal("aliased original input admitted")
	}
}

func TestAuthorityCommandRefusesPartialRetainedInput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires the actual Linux root-owned record contract")
	}
	record := commandRecordFixture(t)
	directory := filepath.Join(record.Options.Directory, "authority-commands")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("private command directory")
	}
	path := filepath.Join(directory, record.Options.Request.ID+".json")
	partial := []byte(`{"version":1`)
	if os.WriteFile(path, partial, 0600) != nil || retainAuthorityCommand(record) == nil {
		t.Fatal("partial retained input replaced")
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, partial) || json.Valid(raw) {
		t.Fatal("partial input was repaired")
	}
}

func TestAuthorityCommandConcurrentInputsRetainOneOriginal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Requires the actual Linux root-owned record contract")
	}
	record := commandRecordFixture(t)
	var group sync.WaitGroup
	results := make(chan string, 8)
	start := make(chan struct{})
	for _, digit := range "12345678" {
		candidate := record
		candidate.Options.ServiceFingerprint = strings.Repeat(string(digit), 64)
		group.Go(func() {
			<-start
			if retainAuthorityCommand(candidate) == nil {
				results <- candidate.Options.ServiceFingerprint
			}
		})
	}
	close(start)
	group.Wait()
	close(results)
	var winner string
	for fingerprint := range results {
		if winner != "" {
			t.Fatal("conflicting original inputs both admitted")
		}
		winner = fingerprint
	}
	loaded, err := readAuthorityCommand(record.Options.Directory, record.Options.Request.ID)
	if winner == "" || err != nil || loaded.Options.ServiceFingerprint != winner || retainAuthorityCommand(loaded) != nil {
		t.Fatal("one durable winner and its exact retry required", err)
	}
}
