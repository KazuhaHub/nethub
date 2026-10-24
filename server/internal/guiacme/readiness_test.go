package guiacme

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountReadinessWithoutOrderListing(t *testing.T) {
	for _, test := range []struct {
		name       string
		omitOrders bool
	}{{"with_listing", false}, {"without_listing", true}} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, fixture, _ := orderFixtureWithAccount(t, func(f *accountFixture) { f.omitOrders = test.omitOrders })
			state, _, err := store.load()
			if err != nil || state.URI != fixture.accountURI || (state.OrdersURL == "") != test.omitOrders {
				t.Fatal("signed account response did not persist the expected metadata", err)
			}
			checkReady := func(s *AccountStore) {
				t.Helper()
				before, err := os.ReadFile(s.path("account.json"))
				if err != nil {
					t.Fatal(err)
				}
				counts := fixture.counts()
				if err := s.Ready(ctx); err != nil {
					t.Fatal("registered account was not ready", err)
				}
				after, err := os.ReadFile(s.path("account.json"))
				if err != nil || !bytes.Equal(before, after) || fixture.counts() != counts {
					t.Fatal("readiness rewrote account state or contacted the CA", err)
				}
			}
			checkReady(store)
			parent := filepath.Dir(store.directory)
			backup := filepath.Join(parent, "registered-backup")
			if err := store.Backup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			restored, err := NewAccountStore(filepath.Join(parent, "restored"), store.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := restored.Restore(ctx, backup); err != nil {
				t.Fatal(err)
			}
			checkReady(restored)
			if err := restored.VerifyBackup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			csr, public := orderRequest(t)
			order, err := restored.CreateOrder(ctx, csr, orderHost, public)
			if err != nil || order.URI != fixture.server.URL+"/order/one" || fixture.counts().creates != 1 || fixture.counts().orders != 1 {
				t.Fatal("order did not use the retained account and directory endpoint", err)
			}
			for _, bad := range []struct {
				name   string
				mutate func(*accountState)
			}{
				{"missing_account", func(s *accountState) { s.URI = "" }},
				{"foreign_account", func(s *accountState) { s.URI = "https://other.example.test/account" }},
				{"foreign_listing", func(s *accountState) { s.OrdersURL = "https://other.example.test/orders" }},
			} {
				t.Run(bad.name, func(t *testing.T) {
					s, err := NewAccountStore(filepath.Join(parent, bad.name), store.config)
					if err != nil {
						t.Fatal(err)
					}
					if err := s.Restore(ctx, backup); err != nil {
						t.Fatal(err)
					}
					invalid := state
					bad.mutate(&invalid)
					if err := s.save(invalid); err != nil {
						t.Fatal(err)
					}
					before, err := os.ReadFile(s.path("account.json"))
					if err != nil {
						t.Fatal(err)
					}
					counts := fixture.counts()
					if err := s.Ready(ctx); err != ErrState {
						t.Fatal("invalid account metadata was admitted", err)
					}
					after, err := os.ReadFile(s.path("account.json"))
					if err != nil || !bytes.Equal(before, after) || fixture.counts() != counts {
						t.Fatal("refusal repaired state or contacted the CA", err)
					}
				})
			}
		})
	}
}
