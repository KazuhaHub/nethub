package guiacme

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func storeFixture(t *testing.T) (*AccountStore, *accountFixture, Config) {
	t.Helper()
	f, config := fixture(t)
	config.Key = nil
	s, err := NewAccountStore(filepath.Join(t.TempDir(), "account"), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, key, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.key = key
	f.mu.Unlock()
	return s, f, config
}

func TestDurableAccountOfflineInitializationAndIdentity(t *testing.T) {
	s, f, config := storeFixture(t)
	before, key, err := s.load()
	if err != nil || before.URI != "" || !validKey(key) || f.counts().requests != 0 {
		t.Fatal("offline initialization performed network work")
	}
	if encoded, _ := json.Marshal(s); string(encoded) != "{}" {
		t.Fatal("private store exported through ordinary JSON")
	}
	if _, err := s.EnsureAccount(context.Background(), false, ""); err != ErrConsent {
		t.Fatal("implicit registration")
	}
	a, err := s.EnsureAccount(context.Background(), true, f.terms)
	if err != nil || a.URI != f.accountURI {
		t.Fatalf("account registration: %v", err)
	}
	state, _, err := s.load()
	if err != nil || state.Key != before.Key || state.URI != a.URI {
		t.Fatal("private identity was not persisted with the same key")
	}
	info, _ := os.Stat(s.path("account.json"))
	reopened, err := NewAccountStore(s.directory, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.EnsureAccount(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(s.path("account.json"))
	if !os.SameFile(info, after) || f.counts().creates != 1 {
		t.Fatal("unchanged account was rewritten or registered again")
	}
	if reopened.config.Roots == config.Roots || !reopened.config.Roots.Equal(config.Roots) {
		t.Fatal("mutable caller trust pool retained")
	}
}

func TestDurableAccountRecoversLostRegistrationResponse(t *testing.T) {
	s, f, config := storeFixture(t)
	before, _, _ := s.load()
	f.loseCreate = true
	if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != ErrRemote {
		t.Fatal("lost response not classified")
	}
	failed, _, _ := s.load()
	if failed.URI != "" || failed.Key != before.Key || f.counts().creates != 1 {
		t.Fatal("ambiguous registration discarded its durable key")
	}
	next, err := NewAccountStore(s.directory, config)
	if err != nil {
		t.Fatal(err)
	}
	a, err := next.EnsureAccount(context.Background(), false, "")
	after, _, loadError := next.load()
	if err != nil || loadError != nil || a.URI != f.accountURI || after.Key != before.Key || after.URI != a.URI || f.counts().creates != 1 {
		t.Fatal("registration recovery changed the account key or created another account")
	}
}

func TestLostAccountStateOrLeaseNeverGeneratesReplacement(t *testing.T) {
	for _, name := range []string{"account.json", "account.lock"} {
		t.Run(name, func(t *testing.T) {
			s, f, _ := storeFixture(t)
			if os.Remove(s.path(name)) != nil {
				t.Fatal("fixture removal")
			}
			if err := s.Initialize(context.Background()); err != ErrState {
				t.Fatal("lost namespace was reinitialized")
			}
			if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != ErrState {
				t.Fatal("missing state was initialized by ordinary work")
			}
			if _, err := os.Lstat(s.path(name)); !os.IsNotExist(err) || f.counts().requests != 0 {
				t.Fatal("lost namespace silently recreated")
			}
		})
	}
}

func TestAccountStorePolicyAndCorruptionFailBeforeNetwork(t *testing.T) {
	for _, kind := range []string{"directory", "origin", "contact", "duplicate", "unknown", "key", "account-origin", "oversized", "trailer"} {
		t.Run(kind, func(t *testing.T) {
			s, f, config := storeFixture(t)
			data, err := os.ReadFile(s.path("account.json"))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				config.DirectoryURL = f.server.URL + "/different-directory"
			case "origin":
				config.AdditionalOrigins = []string{"https://other.example.test"}
			case "contact":
				config.ContactEmail = "changed@example.test"
			case "duplicate":
				data = []byte(strings.Replace(string(data), `"version": 1`, `"version": 1, "version": 1`, 1))
			case "unknown":
				data = append(data[:len(data)-2], []byte(",\n\"unknown\":true\n}\n")...)
			case "key", "account-origin":
				state, _, _ := s.load()
				if kind == "key" {
					state.Key = "not-a-key"
				} else {
					state.URI = "https://other.example.test/account"
				}
				encoded, _ := json.MarshalIndent(state, "", "  ")
				data = append(encoded, '\n')
			case "oversized":
				data = append(data, []byte(strings.Repeat(" ", accountStateLimit))...)
			case "trailer":
				data = append(data, []byte("{}")...)
			}
			if err := os.WriteFile(s.path("account.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			next, err := NewAccountStore(s.directory, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := next.EnsureAccount(context.Background(), true, f.terms); err != ErrState {
				t.Fatal("unsafe private state accepted")
			}
			after, _ := os.ReadFile(s.path("account.json"))
			if string(after) != string(data) || f.counts().requests != 0 {
				t.Fatal("failed state was overwritten or contacted the CA")
			}
		})
	}
}

func TestAccountNamespaceLeaseAndCancellation(t *testing.T) {
	s, f, _ := storeFixture(t)
	lease, err := s.lease(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != ErrBusy {
		t.Fatal("OS lease did not exclude another operation")
	}
	if err := s.Initialize(context.Background()); err != ErrBusy {
		t.Fatal("offline initializer ignored the lease")
	}
	accountRelease(lease)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.EnsureAccount(ctx, true, f.terms); err != ErrCancelled {
		t.Fatal("cancelled account operation")
	}
	if f.counts().requests != 0 {
		t.Fatal("excluded or cancelled operation contacted CA")
	}
}

func TestAccountKnownIdentityAndForeignNamespaceAreRetained(t *testing.T) {
	s, f, _ := storeFixture(t)
	if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.path("account.json"))
	f.mu.Lock()
	f.accountURI = f.server.URL + "/account/changed"
	f.mu.Unlock()
	if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != ErrAccount {
		t.Fatal("known account identity replaced")
	}
	after, _ := os.ReadFile(s.path("account.json"))
	if string(before) != string(after) || f.counts().creates != 1 {
		t.Fatal("mismatched identity persisted or created another account")
	}
	root := filepath.Join(t.TempDir(), "foreign")
	if os.Mkdir(root, 0700) != nil {
		t.Fatal("fixture directory")
	}
	if os.WriteFile(filepath.Join(root, "retain"), []byte("foreign data"), 0600) != nil {
		t.Fatal("fixture file")
	}
	other, err := NewAccountStore(root, s.config)
	if err != nil {
		t.Fatal(err)
	}
	if other.Initialize(context.Background()) != ErrState {
		t.Fatal("foreign namespace adopted")
	}
	if data, _ := os.ReadFile(filepath.Join(root, "retain")); string(data) != "foreign data" {
		t.Fatal("foreign data changed")
	}
}
