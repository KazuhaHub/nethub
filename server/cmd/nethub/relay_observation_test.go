package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestObservationConfigurationRequiresBothPrivateCredentialFiles(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		var origin, userFile, passwordFile string
		if mask&1 != 0 {
			origin = "http://127.0.0.1:7500"
		}
		if mask&2 != 0 {
			userFile = "user-file"
		}
		if mask&4 != 0 {
			passwordFile = "password-file"
		}
		if validObservationFlags(origin, userFile, passwordFile) != (mask == 0 || mask == 7) {
			t.Fatal("partial observation configuration accepted")
		}
	}
	directory := t.TempDir()
	userFile := filepath.Join(directory, "admin-user")
	passwordFile := filepath.Join(directory, "admin-password")
	if err := os.WriteFile(userFile, []byte("test-admin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if _, err := newObserver("http://127.0.0.1:7500", userFile, passwordFile, nil, logger); err == nil {
		t.Fatal("missing admin password file accepted")
	}
	if err := os.WriteFile(passwordFile, []byte("public-test-only-admin-observation-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newObserver("http://127.0.0.1:7500", userFile, passwordFile, nil, logger); err != nil {
		t.Fatal("valid file-based admin configuration rejected")
	}
}
