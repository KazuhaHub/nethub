package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/jackc/pgx/v5/pgconn"
)

func testSAMLReplayProtection(t *testing.T, ctx context.Context, owner, web, authz, backup *sql.DB) {
	tenant := func() string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('SAML replay fixture') RETURNING id`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first, foreign := tenant(), tenant()
	provider := func(tenant, slug string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO identity_providers(tenant_id,kind,slug,display_name,enabled) VALUES($1,'saml',$2,'SAML fixture',true) RETURNING id`, tenant, slug).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.ExecContext(ctx, `INSERT INTO saml_providers(id,tenant_id,entity_id,metadata_xml,email_attribute) VALUES($1,$2,'https://idp.example.com','fixture-only-not-used-for-validation','mail')`, id, tenant); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, other := provider(first, "one"), provider(first, "two"), provider(foreign, "foreign")
	repository := func(db *sql.DB, tenant string) *ConsoleStore {
		return &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}}
	}
	repo := repository(web, first)
	cache := repo.SAMLReplayCache(a)
	now, expiry := time.Now(), time.Now().Add(30*time.Minute)
	const assertion = "signed-assertion-identifier-for-durable-replay-fixture"
	if seen, err := cache.SeenOrAdd(ctx, assertion, expiry, now); err != nil || seen {
		t.Fatal("first assertion could not be recorded", err)
	}
	digest := sha256.Sum256([]byte(assertion))
	var stored []byte
	var storedExpiry time.Time
	if err := owner.QueryRowContext(ctx, `SELECT assertion_hash,expires_at FROM saml_replays WHERE tenant_id=$1 AND provider_id=$2`, first, a).Scan(&stored, &storedExpiry); err != nil || !bytes.Equal(stored, digest[:]) || storedExpiry.Sub(expiry).Abs() > time.Microsecond {
		t.Fatal("replay record lost its hash or full protection window", err)
	}
	// A fresh pool/store proves the record is not process-local cache state.
	reopened, err := OpenRole(ctx, DatabaseConfig{Host: "127.0.0.1", Port: 5432, Database: "nethub", PasswordFile: "/run/secrets/pg_nethub_web", SSLMode: "disable"}, "nethub_web")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if seen, err := repository(reopened, first).SAMLReplayCache(a).SeenOrAdd(ctx, assertion, expiry, now); err != nil || !seen {
		t.Fatal("fresh store forgot durable replay state", err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE identity_providers SET revision=revision+1 WHERE id=$1`, a); err != nil {
		t.Fatal(err)
	}
	if seen, err := cache.SeenOrAdd(ctx, assertion, now.Add(3*time.Hour), now.Add(2*time.Hour)); err != nil || !seen {
		t.Fatal("provider revision or caller clock erased replay protection", err)
	}
	if seen, err := repo.SAMLReplayCache(b).SeenOrAdd(ctx, assertion, expiry, now); err != nil || seen {
		t.Fatal("independent provider shared an assertion namespace", err)
	}
	if _, err := repository(web, foreign).SAMLReplayCache(a).SeenOrAdd(ctx, "foreign-write", expiry, now); !errors.Is(err, sso.ErrFlow) {
		t.Fatal("foreign tenant could write provider replay state")
	}
	if seen, err := repository(web, foreign).SAMLReplayCache(other).SeenOrAdd(ctx, assertion, expiry, now); err != nil || seen {
		t.Fatal("independent tenant shared replay state", err)
	}
	t.Run("concurrent_single_use", func(t *testing.T) {
		var winners, repeats atomic.Int32
		var group sync.WaitGroup
		failures := make(chan error, 8)
		for range 8 {
			group.Go(func() {
				seen, err := repository(web, first).SAMLReplayCache(a).SeenOrAdd(ctx, "parallel-signed-assertion", expiry, now)
				if err != nil {
					failures <- err
				} else if seen {
					repeats.Add(1)
				} else {
					winners.Add(1)
				}
			})
		}
		group.Wait()
		close(failures)
		for err := range failures {
			t.Error("concurrent replay store failed", err)
		}
		if winners.Load() != 1 || repeats.Load() != 7 {
			t.Fatal("parallel assertions did not produce exactly one first acceptance")
		}
	})
	if _, err := owner.ExecContext(ctx, `UPDATE identity_providers SET enabled=false WHERE id=$1`, a); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.SeenOrAdd(ctx, "disabled-provider-assertion", expiry, now); !errors.Is(err, sso.ErrFlow) {
		t.Fatal("disabled provider wrote replay state")
	}
	if _, err := owner.ExecContext(ctx, `UPDATE identity_providers SET enabled=true WHERE id=$1`, a); err != nil {
		t.Fatal(err)
	}
	for _, role := range []*sql.DB{authz, backup} {
		tx, err := role.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, first)
		if err == nil {
			query := `DELETE FROM saml_replays`
			if role == authz {
				query = `SELECT * FROM saml_replays`
			}
			_, err = tx.ExecContext(ctx, query)
		}
		tx.Rollback()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatal("replay table role boundary failed", err)
		}
	}
	var backupCount int
	if err := backup.QueryRowContext(ctx, `SELECT count(*) FROM saml_replays WHERE tenant_id=$1`, first).Scan(&backupCount); err != nil || backupCount != 3 {
		t.Fatal("backup could not read scoped replay evidence", err)
	}
	t.Run("capacity_preserves_unexpired_assertions", func(t *testing.T) {
		_, err := owner.ExecContext(ctx, `INSERT INTO saml_replays(tenant_id,provider_id,assertion_hash,expires_at) SELECT $1,$2,digest('saml-capacity-'||g::text,'sha256'),clock_timestamp()+interval '1 hour' FROM generate_series(1,10000-(SELECT count(*)::int FROM saml_replays WHERE tenant_id=$1)) g`, first, a)
		if err != nil {
			t.Fatal(err)
		}
		if seen, err := cache.SeenOrAdd(ctx, assertion, expiry, now); err != nil || !seen {
			t.Fatal("capacity evicted an accepted assertion", err)
		}
		if _, err := cache.SeenOrAdd(ctx, "new-at-capacity", expiry, now); !errors.Is(err, authsaml.ErrReplayCacheFull) {
			t.Fatal("full replay store accepted a fresh assertion", err)
		}
		if _, err := owner.ExecContext(ctx, `UPDATE saml_replays SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE tenant_id=$1 AND assertion_hash=digest('saml-capacity-1','sha256')`, first); err != nil {
			t.Fatal(err)
		}
		var winners, refused atomic.Int32
		var group sync.WaitGroup
		for i := range 8 {
			group.Go(func() {
				seen, err := cache.SeenOrAdd(ctx, fmt.Sprintf("final-capacity-slot-%d", i), expiry, now)
				if errors.Is(err, authsaml.ErrReplayCacheFull) {
					refused.Add(1)
				} else if err == nil && !seen {
					winners.Add(1)
				} else {
					t.Error("unexpected capacity outcome", err)
				}
			})
		}
		group.Wait()
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM saml_replays WHERE tenant_id=$1`, first).Scan(&count); err != nil || count != 10000 || winners.Load() != 1 || refused.Load() != 7 {
			t.Fatal("expired cleanup or multi-instance capacity admission exceeded its bound", err)
		}
		if seen, err := cache.SeenOrAdd(ctx, assertion, expiry, now); err != nil || !seen {
			t.Fatal("capacity recovery evicted a still-valid assertion", err)
		}
	})
	closed := repository(reopened, first).SAMLReplayCache(a)
	reopened.Close()
	if _, err := closed.SeenOrAdd(ctx, "closed-database-assertion", expiry, now); !errors.Is(err, sso.ErrFlow) {
		t.Fatal("database outage did not fail closed")
	}
	t.Log("SAML replay SQL verified hashed provider/tenant scopes, fresh-pool durability, eight-way single use, caller-clock and revision resistance, role boundaries and fail-closed bounded capacity")
}
