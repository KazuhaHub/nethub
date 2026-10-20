//go:build !windows

package guiacme

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAccountBackupUnixBoundariesAndRecoveryPreservation(t *testing.T) {
	for _, kind := range []string{"state-symlink", "state-hardlink", "lease-symlink", "lease-hardlink", "state-mode", "directory-mode", "parent-mode", "parent-alias"} {
		t.Run(kind, func(t *testing.T) {
			s, f, config := storeFixture(t)
			ctx := context.Background()
			backup := filepath.Join(t.TempDir(), "backup")
			if err := s.Backup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			b, err := NewAccountStore(backup, config)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(s.path("account.json"))
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			data := []byte("retain outside file")
			if kind == "state-symlink" || kind == "state-hardlink" {
				data = bytes.Clone(before)
			}
			if kind == "lease-symlink" || kind == "lease-hardlink" {
				data = nil
			}
			if err := os.WriteFile(outside, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "state-symlink", "state-hardlink", "lease-symlink", "lease-hardlink":
				name := "account.json"
				if kind == "lease-symlink" || kind == "lease-hardlink" {
					name = "account.lock"
				}
				if err := os.Remove(b.path(name)); err != nil {
					t.Fatal(err)
				}
				if kind == "state-hardlink" || kind == "lease-hardlink" {
					err = os.Link(outside, b.path(name))
				} else {
					err = os.Symlink(outside, b.path(name))
				}
				if err != nil {
					t.Fatal(err)
				}
			case "state-mode":
				err = os.Chmod(b.path("account.json"), 0644)
			case "directory-mode":
				err = os.Chmod(backup, 0755)
			case "parent-mode":
				parent := filepath.Dir(backup)
				err = os.Chmod(parent, 0777)
				defer os.Chmod(parent, 0700)
			case "parent-alias":
				alias := filepath.Join(t.TempDir(), "alias")
				err = os.Symlink(filepath.Dir(backup), alias)
				backup = filepath.Join(alias, "backup")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyBackup(ctx, backup); err != ErrState {
				t.Fatal("unsafe backup verified", err)
			}
			if err := s.Restore(ctx, backup); err != ErrState {
				t.Fatal("unsafe backup restored", err)
			}
			if err := s.Backup(ctx, backup); err != ErrState {
				t.Fatal("unsafe backup repaired", err)
			}
			after, err := os.ReadFile(s.path("account.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("source identity changed", err)
			}
			retained, err := os.ReadFile(outside)
			if err != nil || !bytes.Equal(data, retained) {
				t.Fatal("outside file changed", err)
			}
			if f.counts().requests != 0 {
				t.Fatal("unsafe backup contacted CA")
			}
		})
	}
}

func TestAccountBackupAndRecoveryRestrictiveUmask(t *testing.T) {
	s, _, config := storeFixture(t)
	backup := filepath.Join(t.TempDir(), "backup")
	destination := filepath.Join(t.TempDir(), "restored")
	previous := unix.Umask(0777)
	defer unix.Umask(previous)
	if err := s.Backup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	restored, err := NewAccountStore(destination, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{backup, destination} {
		for path, mode := range map[string]os.FileMode{directory: 0700, filepath.Join(directory, "account.json"): 0600, filepath.Join(directory, "account.lock"): 0600} {
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != mode || !accountOwned(info) {
				t.Fatal("private backup/recovery mode or ownership", err)
			}
		}
	}
}
