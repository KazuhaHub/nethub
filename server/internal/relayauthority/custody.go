package relayauthority

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

const CustodyPhrase = "I HAVE VERIFIED THE INDEPENDENT RELAY AUTHORITY BACKUP"

// Custody records an explicit operator assertion, not proof of off-host storage.
// Paths remain in the protected receipt, never in a public generation response.
type Custody struct {
	Version        int       `json:"version"`
	Source         string    `json:"candidate_directory"`
	Backup         string    `json:"backup_directory"`
	MetadataDigest string    `json:"metadata_sha256"`
	Previous       string    `json:"previous_root_fingerprint"`
	Next           string    `json:"next_root_fingerprint"`
	AcknowledgedAt time.Time `json:"acknowledged_at"`
}

func custodyInputs(source, backup, receipt string, now time.Time) (Candidate, error) {
	c, err := Load(source, now)
	if err != nil || VerifyBackup(source, backup, now) != nil {
		return Candidate{}, ErrCandidate
	}
	if !filepath.IsAbs(receipt) || filepath.Clean(receipt) != receipt || overlap(source, receipt) || overlap(backup, receipt) {
		return Candidate{}, ErrCandidate
	}
	parent := filepath.Dir(receipt)
	if !canonical(parent) {
		return Candidate{}, ErrCandidate
	}
	if _, err := protected(parent, true); err != nil {
		return Candidate{}, ErrCandidate
	}
	return c, nil
}

func metadataDigest(c Candidate) string { raw, _ := json.Marshal(c.Metadata); return digest(raw) }

func readCustody(path string) (Custody, error) {
	var value Custody
	raw, err := read(path, 16384)
	if err != nil {
		return value, ErrCandidate
	}
	fields, err := boundedjson.Object(bytes.NewReader(raw))
	if err != nil || len(fields) != 7 {
		return value, ErrCandidate
	}
	if json.Unmarshal(raw, &value) != nil {
		return value, ErrCandidate
	}
	encoded, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, append(encoded, '\n')) {
		return Custody{}, ErrCandidate
	}
	return value, nil
}

func matchesCustody(v Custody, c Candidate, source, backup string, now time.Time) bool {
	return v.Version == 1 && v.Source == source && v.Backup == backup && v.MetadataDigest == metadataDigest(c) &&
		v.Previous == c.Metadata.Previous && v.Next == c.Metadata.Next && !v.AcknowledgedAt.IsZero() &&
		!v.AcknowledgedAt.Before(c.Metadata.PreparedAt) && !v.AcknowledgedAt.After(now.Add(5*time.Second))
}

// AcknowledgeBackup writes an immutable receipt only after exact independent
// copies pass validation. An exact retry keeps the first timestamp; a different
// source/backup/identity cannot reuse the receipt path. It changes no active state.
func AcknowledgeBackup(source, backup, path, phrase string, now time.Time) (Custody, error) {
	if phrase != CustodyPhrase {
		return Custody{}, ErrCandidate
	}
	c, err := custodyInputs(source, backup, path, now)
	if err != nil {
		return Custody{}, ErrCandidate
	}
	if _, err := os.Lstat(path); err == nil {
		v, err := readCustody(path)
		if err != nil || !matchesCustody(v, c, source, backup, now) {
			return Custody{}, ErrCandidate
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return Custody{}, ErrCandidate
		}
		before, statErr := os.Lstat(path)
		opened, openErr := f.Stat()
		if statErr != nil || openErr != nil || !os.SameFile(before, opened) || !owned(opened) {
			f.Close()
			return Custody{}, ErrCandidate
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil || closeErr != nil || syncDirectory(filepath.Dir(path)) != nil {
			return Custody{}, ErrCandidate
		}
		return v, nil
	} else if !os.IsNotExist(err) {
		return Custody{}, ErrCandidate
	}
	v := Custody{Version: 1, Source: source, Backup: backup, MetadataDigest: metadataDigest(c), Previous: c.Metadata.Previous, Next: c.Metadata.Next, AcknowledgedAt: now.UTC()}
	if !matchesCustody(v, c, source, backup, now) {
		return Custody{}, ErrCandidate
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Custody{}, ErrCandidate
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Custody{}, ErrCandidate
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || syncDirectory(filepath.Dir(path)) != nil {
		return Custody{}, ErrCandidate
	}
	return VerifyCustody(source, backup, path, now)
}

// VerifyCustody always checks both current file sets again. A stored timestamp
// or previously successful flag cannot authorize missing, replaced or aliased keys.
func VerifyCustody(source, backup, path string, now time.Time) (Custody, error) {
	c, err := custodyInputs(source, backup, path, now)
	if err != nil {
		return Custody{}, ErrCandidate
	}
	v, err := readCustody(path)
	if err != nil || !matchesCustody(v, c, source, backup, now) {
		return Custody{}, ErrCandidate
	}
	return v, nil
}
