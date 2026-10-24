package guiacme

import (
	"context"
	"path/filepath"
	"testing"
)

func TestContactlessAccountBackupAndRecovery(t *testing.T) {
	ctx := context.Background()
	f, config := fixture(t)
	config.Key = nil
	config.ContactEmail = ""
	f.mu.Lock()
	f.expectedContact = nil
	f.mu.Unlock()
	root := t.TempDir()
	store, err := NewAccountStore(filepath.Join(root, "account"), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	initial, key, err := store.load()
	if err != nil || f.counts().requests != 0 {
		t.Fatal("offline identity initialization failed or contacted the CA")
	}
	f.mu.Lock()
	f.key = key
	f.mu.Unlock()
	backup := filepath.Join(root, "initial-backup")
	if err := store.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyBackup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	for _, consent := range []struct {
		create bool
		terms  string
	}{{false, ""}, {true, f.terms + "/old"}} {
		if _, err := store.EnsureAccount(ctx, consent.create, consent.terms); err != ErrConsent {
			t.Fatal("missing or stale consent admitted contactless registration")
		}
	}
	if f.counts().creates != 0 {
		t.Fatal("contactless consent refusal created an account")
	}
	f.mu.Lock()
	f.loseCreate = true
	f.mu.Unlock()
	if _, err := store.EnsureAccount(ctx, true, f.terms); err != ErrRemote {
		t.Fatal("lost registration response was not reported")
	}
	if f.counts().creates != 1 {
		t.Fatal("contactless registration did not create exactly one remote identity")
	}
	reopened, err := NewAccountStore(store.directory, config)
	if err != nil {
		t.Fatal(err)
	}
	account, err := reopened.EnsureAccount(ctx, false, "")
	if err != nil || account.URI != f.accountURI || f.counts().creates != 1 {
		t.Fatal("contactless lookup did not recover the same registered identity")
	}
	registered := filepath.Join(root, "registered-backup")
	if err := reopened.Backup(ctx, registered); err != nil {
		t.Fatal(err)
	}
	restored, err := NewAccountStore(filepath.Join(root, "restored"), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(ctx, registered); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.EnsureAccount(ctx, false, ""); err != nil {
		t.Fatal("restored contactless account lookup failed")
	}
	state, _, err := restored.load()
	if err != nil || state.Key != initial.Key || state.URI != account.URI || f.counts().creates != 1 {
		t.Fatal("restoration changed the key or account identity")
	}
	f.mu.Lock()
	f.accountURI = f.server.URL + "/account/different"
	f.mu.Unlock()
	if _, err := restored.EnsureAccount(ctx, true, f.terms); err != ErrAccount || f.counts().creates != 1 {
		t.Fatal("contactless lookup replaced a mismatched known account")
	}
}
