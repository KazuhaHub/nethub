package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupCLIRejectsUnsafeOrMixedOptions(t *testing.T) {
	base := t.TempDir()
	enteredPassword := strings.Repeat("x", 40)
	for _, args := range [][]string{
		{"backup", "unknown"},
		{"backup", "run", "--fingerprint", "caller-proof"},
		{"backup", "serve", "--password", enteredPassword},
		{"backup", "run", "--timeout", "0s"},
		{"backup", "run", "--retention-days", "0"},
		{"backup", "run", "--port", "65536"},
		{"backup", "run", "--max-bytes", "-1"},
		{"backup", "health", "--max-age", "0s"},
		{"backup", "health", "--host", "database"},
		{"doctor", "--recent-backup", "--audit"},
		{"doctor", "--recent-backup", "--health-url", "http://127.0.0.1:1/healthz"},
		{"doctor", "--recent-backup", "--password-file", filepath.Join(base, "password"), "--backup-directory", base, "--backup-timeout", "31m"},
		{"doctor", "--health-url", "http://127.0.0.1:1/healthz", "--backup-max-age", "48h"},
	} {
		name := strings.Join(args[:2], "_")
		if len(args) > 2 {
			name += "_" + args[2]
		}
		t.Run(name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if status := run(args, &out, &diagnostic); status != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
				t.Fatalf("unexpected option result: %d", status)
			}
			if strings.Contains(diagnostic.String(), enteredPassword) {
				t.Fatal("literal password echoed in diagnostic")
			}
		})
	}
}

func TestBackupHelpDoesNotStartAWorker(t *testing.T) {
	for _, args := range [][]string{{"backup", "help"}, {"backup", "run", "--help"}, {"backup", "serve", "--help"}, {"backup", "health", "--help"}} {
		var out, diagnostic bytes.Buffer
		if status := run(args, &out, &diagnostic); status != 0 || out.Len()+diagnostic.Len() == 0 {
			t.Fatalf("help result: %d", status)
		}
	}
}
