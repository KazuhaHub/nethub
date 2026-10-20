package guiacme

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentTermsAreFreshReadOnlyAndDoNotAccept(t *testing.T) {
	s, f, _ := storeFixture(t)
	ctx := context.Background()
	before, err := os.ReadFile(s.path("account.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, terms := range []string{f.terms, "https://terms.example.test/changed", "", "data:text/plain,Current%20agreement"} {
		f.mu.Lock()
		f.terms = terms
		f.mu.Unlock()
		value, err := s.CurrentTerms(ctx)
		if err != nil || value != terms {
			t.Fatal("stale/mismatched current terms", err)
		}
	}
	after, err := os.ReadFile(s.path("account.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("terms discovery changed durable identity", err)
	}
	counts := f.counts()
	if counts.requests != 4 || counts.creates != 0 || counts.lookups != 0 || counts.orders != 0 {
		t.Fatal("terms review looked up/registered an account")
	}
	if _, err := s.EnsureAccount(ctx, false, ""); err != ErrConsent {
		t.Fatal("discovery implicitly accepted current terms", err)
	}
}

func TestTermsDiscoveryRejectsUnsafeOrUntrustedDirectory(t *testing.T) {
	for _, kind := range []string{"untrusted-tls", "changed-origin", "invalid-terms", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f, config := fixture(t)
			switch kind {
			case "untrusted-tls":
				config.Roots = nil
			case "changed-origin":
				f.orderOrigin = "https://other.example.test"
			case "invalid-terms":
				f.terms = "data:text/html,invalid"
			case "oversized":
				f.terms = "https://terms.example.test/" + strings.Repeat("a", 2048)
			}
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if value, err := client.CurrentTerms(context.Background()); err != ErrRemote || value != "" {
				t.Fatal("untrusted directory terms exposed", err)
			}
			if f.counts().creates != 0 || f.counts().lookups != 0 {
				t.Fatal("failed discovery changed account")
			}
		})
	}
}

func TestTermsDiscoveryRequiresExistingStateAndHonorsCancellation(t *testing.T) {
	s, f, config := storeFixture(t)
	missing, err := NewAccountStore(filepath.Join(t.TempDir(), "missing"), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.CurrentTerms(context.Background()); err != ErrState {
		t.Fatal("missing state discovered terms", err)
	}
	if _, err := os.Lstat(missing.directory); !os.IsNotExist(err) {
		t.Fatal("terms discovery initialized namespace")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CurrentTerms(ctx); err != ErrCancelled {
		t.Fatal(err)
	}
	if f.counts().requests != 0 {
		t.Fatal("invalid/cancelled discovery contacted CA")
	}
}
