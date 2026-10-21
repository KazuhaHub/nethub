package guiacme

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountOfflineBackupRestoreAndRegisteredRecovery(t *testing.T) {
	s, f, config := storeFixture(t)
	ctx := context.Background()
	backup := filepath.Join(t.TempDir(), "backup")
	before, err := os.ReadFile(s.path("account.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal("exact backup retry", err)
	}
	if err := s.VerifyBackup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if f.counts().requests != 0 {
		t.Fatal("offline backup contacted CA")
	}
	if _, err := s.EnsureAccount(ctx, true, f.terms); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyBackup(ctx, backup); err != nil {
		t.Fatal("pre-registration key backup lost identity", err)
	}
	if err := s.Backup(ctx, backup); err != ErrState {
		t.Fatal("registered metadata overwrote an immutable backup", err)
	}
	recovered, err := NewAccountStore(filepath.Join(t.TempDir(), "recovered"), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Restore(ctx, backup); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(recovered.path("account.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("restore changed backed-up identity")
	}
	if err := recovered.Restore(ctx, backup); err != nil {
		t.Fatal("exact restore retry", err)
	}
	account, err := recovered.EnsureAccount(ctx, false, "")
	if err != nil || account.URI != f.accountURI || f.counts().creates != 1 {
		t.Fatal("restored key did not recover original registered account", err)
	}
	state, _, err := recovered.load()
	original, _, originalErr := s.load()
	if err != nil || originalErr != nil || state != original {
		t.Fatal("recovered account identity differs")
	}
	if err := recovered.Restore(ctx, backup); err != ErrState {
		t.Fatal("older backup overwrote recovered metadata", err)
	}
}

func TestAccountBackupRefusesForeignPartialPolicyAndCancelledState(t *testing.T) {
	s, f, config := storeFixture(t)
	ctx := context.Background()
	for _, target := range []string{s.directory, filepath.Join(s.directory, "nested"), filepath.Dir(s.directory)} {
		if err := s.Backup(ctx, target); err == nil {
			t.Fatal("overlapping account namespace accepted")
		}
		if err := s.Restore(ctx, target); err == nil {
			t.Fatal("overlapping recovery namespace accepted")
		}
	}
	for _, kind := range []string{"foreign", "lease-only", "corrupt", "different-key"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "backup")
			other, err := NewAccountStore(directory, config)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "different-key" {
				if err := other.Initialize(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				name := "foreign"
				data := []byte("retain original data")
				if kind == "lease-only" {
					name = "account.lock"
					data = nil
				}
				if kind == "corrupt" {
					name = "account.json"
					if err := os.WriteFile(filepath.Join(directory, "account.lock"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Backup(ctx, directory); err != ErrState {
				t.Fatal("foreign/partial backup repaired", err)
			}
			if err := s.Restore(ctx, directory); err != ErrState {
				t.Fatal("foreign/partial source restored", err)
			}
		})
	}
	backup := filepath.Join(t.TempDir(), "backup")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	changed := config
	changed.ContactEmail = "other@example.test"
	wrong, err := NewAccountStore(filepath.Join(t.TempDir(), "wrong"), changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Restore(ctx, backup); err != ErrState {
		t.Fatal("different account policy restored", err)
	}
	if _, err := os.Lstat(wrong.directory); !os.IsNotExist(err) {
		t.Fatal("invalid source created recovery namespace")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	unused := filepath.Join(t.TempDir(), "cancelled")
	if err := s.Backup(cancelled, unused); err != ErrCancelled {
		t.Fatal(err)
	}
	if _, err := os.Lstat(unused); !os.IsNotExist(err) {
		t.Fatal("cancelled backup created state")
	}
	if f.counts().requests != 0 {
		t.Fatal("invalid/offline recovery contacted CA")
	}
}

func TestAccountBackupRefusesChangedKnownIdentity(t *testing.T) {
	s, f, config := storeFixture(t)
	ctx := context.Background()
	if _, err := s.EnsureAccount(ctx, true, f.terms); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	b, err := NewAccountStore(backup, config)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := b.load()
	if err != nil {
		t.Fatal(err)
	}
	state.URI += "-changed"
	if err := b.save(state); err != nil {
		t.Fatal(err)
	}
	counts := f.counts()
	if err := s.VerifyBackup(ctx, backup); err != ErrState {
		t.Fatal("changed known account verified", err)
	}
	if f.counts() != counts {
		t.Fatal("backup verification contacted CA")
	}
}

func TestAccountBackupLeaseExclusionAndCorruptSource(t *testing.T) {
	s, _, config := storeFixture(t)
	ctx := context.Background()
	backup := filepath.Join(t.TempDir(), "backup")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	b, err := NewAccountStore(backup, config)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := b.lease(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyBackup(ctx, backup); err != ErrBusy {
		t.Fatal("busy backup verification", err)
	}
	if err := s.Backup(ctx, backup); err != ErrBusy {
		t.Fatal("busy backup overwritten", err)
	}
	accountRelease(lease)
	lease, err = s.lease(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, filepath.Join(t.TempDir(), "unused")); err != ErrBusy {
		t.Fatal("busy source copied", err)
	}
	accountRelease(lease)
	if err := os.WriteFile(b.path("account.json"), []byte("corrupt private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyBackup(ctx, backup); err != ErrState {
		t.Fatal("corrupt backup accepted", err)
	}
}
