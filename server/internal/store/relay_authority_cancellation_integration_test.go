package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

func testRelayAuthorityCancellation(t *testing.T, f *enrollmentFixture, p *relaytrust.Publisher, request relaytrust.SwitchRequest, web *sql.DB) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	cancelled := request
	cancelled.ID = "6546e695-c8f4-45aa-a9ab-75b3660b3fc2"
	first, err := p.CancelSwitch(f.ctx, cancelled, digest)
	if err != nil {
		t.Fatal("durable absent-operation cancellation", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			retry, err := p.CancelSwitch(f.ctx, cancelled, digest)
			if err != nil || !retry.CancelledAt.Equal(first.CancelledAt) {
				t.Error("cancellation retry changed identity/time", err)
			}
		})
	}
	wg.Wait()
	if retry, err := p.ReadCancellation(f.ctx, cancelled.ID); err != nil || !retry.CancelledAt.Equal(first.CancelledAt) {
		t.Fatal("read original cancellation", err)
	}
	if _, err := p.CancelSwitch(f.ctx, cancelled, strings.Repeat("b", 64)); err == nil {
		t.Fatal("cancellation rebound to another local intent")
	}
	changed := cancelled
	changed.NextLeaf = changed.NextRoot
	if _, err := p.CancelSwitch(f.ctx, changed, digest); err == nil {
		t.Fatal("cancellation rebound to another leaf")
	}
	if _, err := p.BeginSwitch(f.ctx, cancelled); err == nil {
		t.Fatal("cancelled operation entered pending")
	}
	var count int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM relay_authority_cancellations WHERE id=$1`, cancelled.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("cancellation retry duplicated history", err)
	}
	for _, statement := range []string{`UPDATE relay_authority_cancellations SET cancelled_at=clock_timestamp() WHERE id=$1`, `DELETE FROM relay_authority_cancellations WHERE id=$1`} {
		if _, err := f.owner.ExecContext(f.ctx, statement, cancelled.ID); err == nil {
			t.Fatal("cancellation history changed")
		}
	}
	if _, err := f.owner.ExecContext(f.ctx, `INSERT INTO relay_authority_switches(id,trust_generation_id,server_name,previous_root,next_root,previous_leaf,next_leaf) VALUES($1,$2,$3,$4,$5,$6,$7)`, cancelled.ID, cancelled.GenerationID, p.ServerName, cancelled.PreviousRoot, cancelled.NextRoot, cancelled.PreviousLeaf, cancelled.NextLeaf); err == nil {
		t.Fatal("raw insert bypassed cancellation ledger")
	}
	for _, db := range []*sql.DB{web, f.repository.DB} {
		if _, err := db.ExecContext(f.ctx, `SELECT * FROM relay_authority_cancellations`); err == nil {
			t.Fatal("raw cancellation table exposed")
		}
		if _, err := db.ExecContext(f.ctx, `SELECT read_relay_authority_cancellation($1,$2)`, cancelled.ID, p.ServerName); err == nil {
			t.Fatal("application role read host cancellation")
		}
	}
	for _, role := range []string{"nethub_authz", "nethub_web", "nethub_issuer"} {
		var grants bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT has_table_privilege($1,'public.relay_authority_cancellations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege($1,'public.relay_authority_cancellations','SELECT,INSERT,UPDATE,REFERENCES')`, role).Scan(&grants); err != nil || grants {
			t.Fatal("raw cancellation grants", err)
		}
	}
	if _, err := issuerSQLInput(f.ctx, []byte(`SET SESSION AUTHORIZATION nethub_issuer; SELECT private_begin_relay_authority_switch_v15(NULL,NULL,NULL,NULL,NULL,NULL,NULL);`)); err == nil {
		t.Fatal("issuer bypassed public cancellation guard through private admission")
	}
	for _, trigger := range []struct{ table, name string }{{"relay_authority_switches", "relay_authority_cancelled_switch_guard"}, {"relay_authority_cancellations", "relay_authority_cancellation_switch_guard"}, {"relay_authority_cancellations", "relay_authority_cancellation_immutable"}} {
		func() {
			if _, err := f.owner.ExecContext(f.ctx, "ALTER TABLE "+trigger.table+" DISABLE TRIGGER "+trigger.name); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := f.owner.ExecContext(f.ctx, "ALTER TABLE "+trigger.table+" ENABLE TRIGGER "+trigger.name); err != nil {
					t.Error(err)
				}
			}()
			if f.repository.Health(f.ctx) == nil {
				t.Fatal("readiness accepted disabled cancellation guard")
			}
			if _, err := p.ReadCancellation(f.ctx, cancelled.ID); err == nil {
				t.Fatal("host read accepted disabled cancellation guard")
			}
		}()
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `GRANT EXECUTE ON FUNCTION private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text) TO nethub_issuer`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `REVOKE EXECUTE ON FUNCTION private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text) FROM nethub_issuer`); err != nil {
				t.Error(err)
			}
		}()
		if f.repository.Health(f.ctx) == nil {
			t.Fatal("readiness accepted exposed private admission bypass")
		}
	}()

	for round := range 2 {
		r := request
		r.ID = fmt.Sprintf("f96b99bc-7941-4dc1-9418-%012x", round+1)
		blocker, err := f.owner.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer blocker.Rollback()
			var holder int
			if err := blocker.QueryRowContext(f.ctx, `SELECT pg_backend_pid() FROM relay_trust_head WHERE singleton FOR UPDATE`).Scan(&holder); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			began := make(chan error, 1)
			aborted := make(chan error, 1)
			go func() { _, err := p.BeginSwitch(ctx, r); began <- err }()
			go func() { _, err := p.CancelSwitch(ctx, r, digest); aborted <- err }()
			reached := false
			for range 300 {
				var waiting int
				if err := f.owner.QueryRowContext(f.ctx, `SELECT count(DISTINCT pid) FROM pg_locks WHERE relation='public.relay_trust_head'::regclass AND mode='RowShareLock' AND granted AND pid<>$1`, holder).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting >= 2 {
					reached = true
					break
				}
				select {
				case err := <-began:
					t.Fatal("begin returned before held-head admission", err)
				default:
				}
				select {
				case err := <-aborted:
					t.Fatal("cancel returned before held-head admission", err)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !reached {
				t.Fatal("both competing operations did not reach the held head")
			}
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			beginErr, cancelErr := <-began, <-aborted
			if (beginErr == nil) == (cancelErr == nil) {
				t.Fatal("begin/cancel race did not have exactly one durable winner", beginErr, cancelErr)
			}
			if beginErr == nil {
				if _, err := p.CancelSwitch(f.ctx, r, digest); err == nil {
					t.Fatal("pending race winner was cancelled")
				}
				if _, err := f.owner.ExecContext(f.ctx, `INSERT INTO relay_authority_cancellations(id,trust_generation_id,server_name,previous_root,next_root,previous_leaf,next_leaf,intent_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.ID, r.GenerationID, p.ServerName, r.PreviousRoot, r.NextRoot, r.PreviousLeaf, r.NextLeaf, digest); err == nil {
					t.Fatal("raw cancellation bypassed switch ledger")
				}
				if _, err := p.FinishSwitch(f.ctx, r, "rolled_back", r.PreviousLeaf); err != nil {
					t.Fatal("restore fixture race winner", err)
				}
				if _, err := p.CancelSwitch(f.ctx, r, digest); err == nil {
					t.Fatal("terminal race winner was cancelled")
				}
			} else if _, err := p.BeginSwitch(f.ctx, r); err == nil {
				t.Fatal("cancelled race winner entered pending")
			}
		}()
	}
	t.Log("Authority cancellation passed immutable exact retries, no admission replay/private bypass, forced-RLS readiness and two real held-head begin/cancel races with one durable winner; database fixture only")
}
