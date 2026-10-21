package guiacme

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Backup copies the complete validated private account into an independent
// protected namespace. Existing backups are immutable: only an exact retry is
// accepted. No key is generated, account contacted, or source state changed.
func (s *AccountStore) Backup(ctx context.Context, directory string) error {
	destination, err := s.independentStore(directory)
	if err != nil {
		return err
	}
	return s.copyAccount(ctx, destination)
}

// Restore explicitly recovers into a new namespace, preserving the backup's key
// and known CA identity. An existing incomplete, corrupt or different namespace
// needs operator review; recovery never repairs it or overwrites its identity.
func (s *AccountStore) Restore(ctx context.Context, backup string) error {
	source, err := s.independentStore(backup)
	if err != nil {
		return err
	}
	return source.copyAccount(ctx, s)
}

// VerifyBackup reads both protected namespaces under their leases. Registration
// may have added public account metadata since an offline pre-registration
// backup. A newer backup cannot supply identity that the current namespace has
// not recovered; registration must not discard that known identity.
func (s *AccountStore) VerifyBackup(ctx context.Context, directory string) error {
	backup, err := s.independentStore(directory)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	sourceLease, err := s.lease(false)
	if err != nil {
		return err
	}
	defer accountRelease(sourceLease)
	backupLease, err := backup.lease(false)
	if err != nil {
		return err
	}
	defer accountRelease(backupLease)
	a, _, err := s.load()
	if err != nil {
		return err
	}
	b, _, err := backup.load()
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if a.Policy != b.Policy || a.Key != b.Key ||
		b.URI != "" && a.URI != b.URI ||
		b.OrdersURL != "" && a.OrdersURL != b.OrdersURL {
		return ErrState
	}
	return nil
}

func (s *AccountStore) independentStore(directory string) (*AccountStore, error) {
	other, err := NewAccountStore(directory, s.config)
	if err != nil {
		return nil, err
	}
	within := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
	}
	if within(s.directory, other.directory) || within(other.directory, s.directory) {
		return nil, ErrState
	}
	return other, nil
}

func (s *AccountStore) copyAccount(ctx context.Context, destination *AccountStore) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	lease, err := s.lease(false)
	if err != nil {
		return err
	}
	defer accountRelease(lease)
	state, _, err := s.load()
	if err != nil {
		return err
	}
	return destination.installAccount(ctx, state)
}

func (s *AccountStore) installAccount(ctx context.Context, state accountState) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if s.checkParent() != nil {
		return ErrState
	}
	if err := os.Mkdir(s.directory, 0700); err == nil {
		if os.Chmod(s.directory, 0700) != nil || accountSync(filepath.Dir(s.directory)) != nil {
			return ErrState
		}
	} else if !os.IsExist(err) {
		return ErrState
	}
	if accountProtected(s.directory, true) != nil {
		return ErrState
	}
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return ErrState
	}
	initialize := len(entries) == 0
	if !initialize && (len(entries) != 2 || entries[0].Name() != "account.json" || entries[1].Name() != "account.lock") {
		return ErrState
	}
	lease, err := s.lease(initialize)
	if err != nil {
		return err
	}
	defer accountRelease(lease)
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if _, err := os.Lstat(s.path("account.json")); err == nil {
		existing, _, err := s.load()
		if err != nil || existing != state {
			return ErrState
		}
		// An earlier attempt may have published bytes but lost a sync result.
		// Re-establish durability before acknowledging the exact retry.
		if accountSync(s.path("account.json")) != nil || accountSync(s.directory) != nil || accountSync(filepath.Dir(s.directory)) != nil {
			return ErrState
		}
		return nil
	} else if !os.IsNotExist(err) || !initialize {
		return ErrState
	}
	if s.save(state) != nil {
		return ErrState
	}
	// Verification reuses the canonical codec, key consistency, ownership, mode,
	// link and immutable policy checks; a successful write alone is insufficient.
	installed, _, err := s.load()
	if err != nil || installed != state {
		return ErrState
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}
