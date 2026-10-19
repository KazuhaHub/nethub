package store

import (
	"errors"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

func testRelayAuthorization(t *testing.T, f *enrollmentFixture, tenant, otherTenant string) {
	record, _, _ := f.fresh(t, tenant)
	assigned, err := f.repository.Register(f.ctx, record, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := f.signer.Verify(assigned.Claim)
	if err != nil {
		t.Fatal(err)
	}
	repository := &RelayStore{DB: f.repository.DB}
	if err := repository.Authorize(f.ctx, identity); err != nil {
		t.Fatal("current signed identity did not pass actual-role authorization")
	}
	for _, kind := range []string{"missing", "tenant", "subdomain", "issued_at"} {
		t.Run(kind, func(t *testing.T) {
			deviceID, subdomain, tenantID, issued := identity.DeviceID, identity.Subdomain, identity.TenantID, assigned.IssuedAt
			switch kind {
			case "missing":
				deviceID = "44444444-4444-4444-8444-444444444444"
			case "tenant":
				tenantID = otherTenant
			case "subdomain":
				subdomain = "another1"
			case "issued_at":
				issued = issued.Add(-time.Microsecond)
			}
			encoded, err := f.signer.Issue(deviceID, subdomain, tenantID, issued)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := f.signer.Verify(encoded)
			if err != nil || !errors.Is(repository.Authorize(f.ctx, payload), relayhook.ErrDenied) {
				t.Fatal("valid signature bypassed current database assignment")
			}
		})
	}
	for _, kind := range []string{"revoked_during_lock", "claim_changed_during_lock"} {
		t.Run(kind, func(t *testing.T) {
			record, _, _ := f.fresh(t, tenant)
			assigned, err := f.repository.Register(f.ctx, record, f.issue)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := f.signer.Verify(assigned.Claim)
			if err != nil {
				t.Fatal(err)
			}
			blocker, err := f.owner.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if _, err := blocker.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, assigned.ID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- repository.Authorize(f.ctx, payload) }()
			waiting := false
			for deadline := time.Now().Add(350 * time.Millisecond); time.Now().Before(deadline); {
				var count int
				if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM pg_locks WHERE NOT granted AND locktype='transactionid'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count > 0 {
					waiting = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !waiting {
				t.Fatal("relay authorization did not reach the expected device lock")
			}
			if kind == "revoked_during_lock" {
				_, err = blocker.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, assigned.ID)
			} else {
				_, err = blocker.ExecContext(f.ctx, `UPDATE devices SET domain_claim_issued_at=domain_claim_issued_at+interval '1 microsecond' WHERE id=$1`, assigned.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, relayhook.ErrDenied) {
					t.Fatal("post-lock revocation or claim replacement was not rejected")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("relay authorization remained blocked")
			}
		})
	}
	// A direct revoked-row lookup must also deny a formerly valid signature.
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, assigned.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.Authorize(f.ctx, identity); !errors.Is(err, relayhook.ErrDenied) {
		t.Fatal("revoked identity passed relay authorization")
	}
}
