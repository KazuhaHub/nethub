//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFixturePublicTrustRemainsReadableUnderPrivateUmask(t *testing.T) {
	// This test is deliberately serial: umask belongs to the process.
	before := syscall.Umask(0077)
	defer syscall.Umask(before)
	directory := filepath.Join(t.TempDir(), "fixture")
	if err := prepare(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		".": 0700, "root.crt": 0644, "origin.crt": 0644,
		"origin.key": 0600, "credentials.json": 0600, "dex-one.json": 0600, "dex-two.json": 0600,
	} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("fixture trust/secret permissions changed under private umask", name, err)
		}
	}
}
