package backupworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/dbbackup"
)

func TestCallerFingerprintCannotSubstituteForDatabaseIdentity(t *testing.T) {
	base := t.TempDir()
	config := Config{Backup: dbbackup.Config{Directory: filepath.Join(base, "archives"), RuntimeDirectory: filepath.Join(base, "runtime"), PasswordFile: filepath.Join(base, "password"), Host: "127.0.0.1", Port: 5432, Database: "nethub", SSLMode: "disable", Timeout: time.Minute, MaxBytes: 1024, DeploymentFingerprint: strings.Repeat("a", 64)}, Retention: 24 * time.Hour}
	if err := Validate(config); !errors.Is(err, ErrOptions) {
		t.Fatalf("caller identity accepted: %v", err)
	}
	if _, err := Attempt(context.Background(), config, dbbackup.WorkerState{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("invalid attempt performed work: %v", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected caller identity changed the filesystem")
	}
}
