package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestAuditRecordIntegrity(t *testing.T) {
	body := []byte(`{"fixture":"private audit data"}`)
	digest := sha256.Sum256(body)
	var state auditChainState
	if err := state.accept(1, nil, digest[:], body, 1); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), state.head...)
	for _, test := range []struct {
		name                   string
		sequence               int64
		previous, digest, body []byte
		version                int
	}{
		{"gap", 3, before, digest[:], body, 2},
		{"link", 2, bytes.Repeat([]byte{1}, 32), digest[:], body, 2},
		{"digest", 2, before, bytes.Repeat([]byte{2}, 32), body, 2},
		{"short digest", 2, before, digest[:31], body, 2},
		{"missing body", 2, before, digest[:], nil, 2},
		{"oversized body", 2, before, digest[:], make([]byte, (1<<20)+1), 2},
		{"future version", 2, before, digest[:], body, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := state.accept(test.sequence, test.previous, test.digest, test.body, test.version); !errors.Is(err, ErrAuditChainInvalid) {
				t.Fatal("invalid record accepted")
			}
			if state.Entries != 1 || state.LegacyEntries != 1 || !bytes.Equal(state.head, before) {
				t.Fatal("failed check advanced the verified prefix")
			}
		})
	}
	if err := state.accept(2, before, digest[:], body, 2); err != nil || state.Entries != 2 || state.LegacyEntries != 1 {
		t.Fatal("mixed-version continuation refused")
	}
}
