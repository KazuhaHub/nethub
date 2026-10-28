package dbbackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func expiredFixture(t *testing.T, config Config, started time.Time, suffix string) string {
	t.Helper()
	name := "nethub-" + started.UTC().Format("20060102T150405Z") + "-" + suffix + ".dump"
	path := filepath.Join(config.Directory, name)
	if err := os.WriteFile(path, []byte("PGDMPsynthetic-expired"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, started, started); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestPrunePreservesLastGoodAndUnmanagedFiles(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	receipt, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	state, err := readState(root)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	retained := "nethub-" + old.Format("20060102T150405Z") + "-0123456789abcdef.dump"
	if err := root.Rename(receipt.Archive, retained); err != nil {
		t.Fatal(err)
	}
	state.AttemptStartedAt = old
	state.AttemptDeadline = old.Add(time.Minute)
	state.LatestSuccess.Archive = retained
	state.LatestSuccess.StartedAt = old
	state.LatestSuccess.CompletedAt = old.Add(time.Second)
	if err := writeState(root, state); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(config.Directory, retained), old, old); err != nil {
		t.Fatal(err)
	}
	expired := expiredFixture(t, config, old.Add(-time.Hour), "1111111111111111")
	freshCopy := expiredFixture(t, config, old.Add(-2*time.Hour), "2222222222222222")
	if err := os.Chtimes(filepath.Join(config.Directory, freshCopy), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(config.Directory, "operator-notes.txt")
	if err := os.WriteFile(notes, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	removed, err := Prune(context.Background(), config.Directory, config.DeploymentFingerprint, 24*time.Hour)
	if err != nil || removed != 1 {
		t.Fatalf("prune result: %d %v", removed, err)
	}
	if _, err := root.Stat(expired); !os.IsNotExist(err) {
		t.Fatal("expired managed archive retained")
	}
	for _, name := range []string{retained, freshCopy, "operator-notes.txt", stateName, ".nethub-backup.lock"} {
		if _, err := root.Stat(name); err != nil {
			t.Fatalf("protected file removed: %s", name)
		}
	}
	if _, err := Verify(context.Background(), config.Directory, config.DeploymentFingerprint, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestPruneUnsafeCandidatePreventsAnyDeletion(t *testing.T) {
	config := syntheticConfig(t)
	producer(t, config, "printf PGDMPsynthetic-archive")
	if _, err := Run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	expired := expiredFixture(t, config, old, "1111111111111111")
	unsafe := filepath.Join(config.Directory, "nethub-"+old.Format("20060102T150405Z")+"-2222222222222222.dump")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, unsafe); err != nil {
		t.Fatal(err)
	}
	if n, err := Prune(context.Background(), config.Directory, config.DeploymentFingerprint, 24*time.Hour); n != 0 || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unsafe candidate accepted: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(config.Directory, expired)); err != nil {
		t.Fatal("preflight failure removed an earlier candidate")
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "outside retained" {
		t.Fatal("outside file changed")
	}
	if err := os.Remove(unsafe); err != nil {
		t.Fatal(err)
	}
	guard, err := lock(config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Prune(context.Background(), config.Directory, config.DeploymentFingerprint, 24*time.Hour); n != 0 || !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent prune accepted: %d %v", n, err)
	}
	guard.Close()
	producer(t, config, "exit 1")
	if _, err := Run(context.Background(), config); !errors.Is(err, ErrDump) {
		t.Fatal("failed producer fixture did not fail")
	}
	if n, err := Prune(context.Background(), config.Directory, config.DeploymentFingerprint, 24*time.Hour); n != 0 || !errors.Is(err, ErrLastAttempt) {
		t.Fatalf("failed latest attempt allowed prune: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(config.Directory, expired)); err != nil {
		t.Fatal("failed latest attempt removed old archive")
	}
}
