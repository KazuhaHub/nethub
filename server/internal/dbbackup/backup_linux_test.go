package dbbackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These producers exercise file/process failure boundaries, not PostgreSQL restore.
func syntheticConfig(t *testing.T) Config {
	t.Helper()
	base := t.TempDir()
	data, runtime := filepath.Join(base, "archives"), filepath.Join(base, "runtime")
	for _, path := range []string{data, runtime} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	password := filepath.Join(base, "password")
	if err := os.WriteFile(password, []byte(strings.Repeat("x", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{Directory: data, RuntimeDirectory: runtime, DeploymentFingerprint: strings.Repeat("a", 64), Host: "postgres", Database: "nethub", PasswordFile: password, SSLMode: "disable", Port: 5432, Timeout: 2 * time.Second, MaxBytes: 1024, dumpBinary: filepath.Join(base, "producer")}
}

func producer(t *testing.T, config Config, command string) {
	t.Helper()
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'pg_dump (PostgreSQL) 16.10\\n'; exit; fi\n" +
		"[ \"$#\" = 2 ] && [ \"$1\" = --format=custom ] && [ \"$2\" = --no-password ] || exit 91\n" +
		"[ \"$PGUSER\" = nethub_backup ] && [ -f \"$PGPASSFILE\" ] && [ -z \"$PGPASSWORD\" ] || exit 92\n" + command + "\n"
	if err := os.WriteFile(config.dumpBinary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticProducerFailurePreservesLastGood(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	first, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	status, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour)
	if err != nil || status.Receipt != first || status.InProgress {
		t.Fatalf("completed verification: %+v %v", status, err)
	}
	for _, tc := range []struct{ name, command string }{
		{"failed process", "printf PGDMPpartial; exit 1"},
		{"invalid header", "printf invalid"},
		{"size limit", "printf PGDMP; head -c 2048 /dev/zero"},
		{"deadline", "sleep 10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			producer(t, config, tc.command)
			if _, err := Run(context.Background(), config); !errors.Is(err, ErrDump) {
				t.Fatalf("failed producer: %v", err)
			}
			if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); !errors.Is(err, ErrLastAttempt) {
				t.Fatalf("failure masked: %v", err)
			}
			root, err := os.OpenRoot(config.Directory)
			if err != nil {
				t.Fatal(err)
			}
			s, err := readState(root)
			root.Close()
			if err != nil || s.LatestSuccess == nil || *s.LatestSuccess != first {
				t.Fatalf("last good receipt lost: %+v %v", s, err)
			}
			for _, directory := range []string{config.Directory, config.RuntimeDirectory} {
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".partial-") || strings.HasPrefix(entry.Name(), "nethub-backup-") {
						t.Fatalf("temporary material retained: %s", entry.Name())
					}
				}
			}
		})
	}
	producer(t, config, "printf PGDMPrecovered")
	if _, err := Run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticArchiveCorruptionAndContention(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	receipt, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := lock(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), config); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent writer: %v", err)
	}
	guard.Close()
	root, err := os.OpenRoot(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	state, err := readState(root)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	state.Outcome = "succeeded"
	state.AttemptStartedAt = state.AttemptStartedAt.Add(time.Second)
	if err := writeState(root, state); !errors.Is(err, ErrIntegrity) {
		root.Close()
		t.Fatalf("incoherent replacement published: %v", err)
	}
	root.Close()
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); err != nil {
		t.Fatalf("refused replacement changed last good state: %v", err)
	}
	archive := filepath.Join(config.Directory, receipt.Archive)
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, time.Hour); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corruption accepted: %v", err)
	}
	if _, err := Verify(context.Background(), config.Directory, strings.Repeat("b", 64), time.Hour); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong deployment accepted: %v", err)
	}
}
