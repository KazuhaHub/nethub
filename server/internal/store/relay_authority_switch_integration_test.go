package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

func certificateDERFingerprint(t *testing.T, data []byte) string {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
		t.Fatal("invalid certificate fixture")
	}
	digest := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(digest[:])
}

func testRelayAuthoritySwitch(t *testing.T, f *enrollmentFixture, p *relaytrust.Publisher, store *RelayTrustStore,
	credential device.Credential, deviceID string, overlap *relaytrust.Generation, request relaytrust.SwitchRequest, tenant string, web *sql.DB) {
	t.Helper()
	testRelayAuthorityCancellation(t, f, p, request, web)
	stale := request
	stale.GenerationID = "56dde2f1-b731-474e-a822-1974623cf25b"
	if _, err := p.BeginSwitch(f.ctx, stale); err == nil {
		t.Fatal("stale switch accepted")
	}
	missing := request
	missing.NextRoot = missing.NextLeaf
	if _, err := p.BeginSwitch(f.ctx, missing); err == nil {
		t.Fatal("switch without both roots accepted")
	}
	intent, err := p.BeginSwitch(f.ctx, request)
	if err != nil || intent.Phase != "pending" {
		t.Fatal("begin authority switch", err)
	}
	if _, err := p.CancelSwitch(f.ctx, request, strings.Repeat("c", 64)); err == nil {
		t.Fatal("pending switch was cancelled")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			retry, err := p.BeginSwitch(f.ctx, request)
			if err != nil || retry.Phase != "pending" || !retry.CreatedAt.Equal(intent.CreatedAt) {
				t.Error("switch retry changed identity", err)
			}
		})
	}
	wg.Wait()
	other := request
	other.ID = "d1ac7fb7-40d5-49fa-b464-dedb422f45e5"
	if _, err := p.BeginSwitch(f.ctx, other); err == nil {
		t.Fatal("second pending switch accepted")
	}
	changed := request
	changed.NextLeaf = changed.NextRoot
	if _, err := p.BeginSwitch(f.ctx, changed); err == nil {
		t.Fatal("existing switch rebound")
	}
	for _, trigger := range []struct{ table, name string }{
		{"devices", "devices_relay_trust_enrollment"},
		{"relay_trust_generations", "relay_trust_authority_switch_fence"},
		{"relay_authority_switches", "relay_authority_switch_immutable"},
	} {
		func() {
			if _, err := f.owner.ExecContext(f.ctx, "ALTER TABLE "+trigger.table+" DISABLE TRIGGER "+trigger.name); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := f.owner.ExecContext(f.ctx, "ALTER TABLE "+trigger.table+" ENABLE TRIGGER "+trigger.name); err != nil {
					t.Error(err)
				}
			}()
			if store.Health(f.ctx) == nil {
				t.Fatal("readiness accepted missing authority fence", trigger.name)
			}
			if _, err := p.ReadSwitch(f.ctx, request.ID); err == nil {
				t.Fatal("host read accepted missing authority fence", trigger.name)
			}
		}()
	}
	if store.Health(f.ctx) != nil {
		t.Fatal("pending intent disabled existing device API")
	}
	if retry, err := p.Publish(f.ctx, overlap.ID, overlap.Bundle().PEM()); err != nil || retry.ID != overlap.ID {
		t.Fatal("pending switch refused exact publication recovery", err)
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `GRANT EXECUTE ON FUNCTION read_relay_authority_switch(uuid,text) TO nethub_web`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `REVOKE EXECUTE ON FUNCTION read_relay_authority_switch(uuid,text) FROM nethub_web`); err != nil {
				t.Error(err)
			}
		}()
		if store.Health(f.ctx) == nil {
			t.Fatal("readiness accepted exposed private switch function")
		}
		if _, err := p.ReadSwitch(f.ctx, request.ID); err == nil {
			t.Fatal("host read accepted exposed private switch function")
		}
	}()
	if current, err := store.Current(f.ctx, credential, deviceID); err != nil || current.ID != overlap.ID {
		t.Fatal("pending switch blocked current trust", err)
	}
	if _, err := store.Acknowledge(f.ctx, credential, deviceID, overlap); err != nil {
		t.Fatal("pending switch blocked application retry", err)
	}
	// A publisher cannot retire the old root while a host may still serve it.
	roots, err := overlap.Bundle().Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range roots {
		if _, err := p.Publish(f.ctx, overlap.ID, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))); err == nil {
			t.Fatal("publication crossed pending authority fence")
		}
	}
	r, _, _ := f.fresh(t, tenant)
	if _, err := f.repository.Register(f.ctx, r, f.issue); err == nil {
		t.Fatal("enrollment crossed pending authority fence")
	}
	f.unused(t, r)
	var available bool
	if err := f.owner.QueryRowContext(f.ctx, `SELECT used_at IS NULL FROM enroll_tokens WHERE token_hash=$1 FOR UPDATE NOWAIT`, r.TokenHash[:]).Scan(&available); err != nil || !available {
		t.Fatal("fenced enrollment consumed or locked token", err)
	}
	for _, db := range []*sql.DB{web, f.repository.DB} {
		if _, err := db.ExecContext(f.ctx, `SELECT * FROM relay_authority_switches`); err == nil {
			t.Fatal("application read private switch table")
		}
		if _, err := db.ExecContext(f.ctx, `SELECT read_relay_authority_switch($1,'relay.example.test')`, request.ID); err == nil {
			t.Fatal("application role read host switch")
		}
	}
	for _, statement := range []string{
		`UPDATE relay_authority_switches SET next_leaf=previous_leaf WHERE id=$1`,
		`UPDATE relay_authority_switches SET phase='committed' WHERE id=$1`,
		`UPDATE relay_authority_switches SET phase='committed',finished_at=clock_timestamp() WHERE id=$1`,
		`UPDATE relay_authority_switches SET phase='committed',observed_leaf=next_leaf WHERE id=$1`,
		`DELETE FROM relay_authority_switches WHERE id=$1`,
	} {
		if _, err := f.owner.ExecContext(f.ctx, statement, request.ID); err == nil {
			t.Fatal("switch identity or incomplete terminal state mutated")
		}
	}
	if _, err := issuerSQLInput(f.ctx, []byte("SET SESSION AUTHORIZATION nethub_issuer; SELECT finish_relay_authority_switch('"+request.ID+"','committed','"+request.PreviousLeaf+"');")); err != nil {
		t.Fatal(err)
	}
	still, err := p.ReadSwitch(f.ctx, request.ID)
	if err != nil || still.Phase != "pending" || !still.CreatedAt.Equal(intent.CreatedAt) {
		t.Fatal("wrong leaf cleared pending fence", err)
	}
	if _, err := p.FinishSwitch(f.ctx, changed, "rolled_back", changed.PreviousLeaf); err == nil {
		t.Fatal("mismatched request resolved fence")
	}
	resolved, err := p.FinishSwitch(f.ctx, request, "rolled_back", request.PreviousLeaf)
	if err != nil || resolved.Phase != "rolled_back" {
		t.Fatal("rollback report failed", err)
	}
	if _, err := p.CancelSwitch(f.ctx, request, strings.Repeat("c", 64)); err == nil {
		t.Fatal("completed switch was cancelled")
	}
	retry, err := p.FinishSwitch(f.ctx, request, "rolled_back", request.PreviousLeaf)
	if err != nil || !retry.FinishedAt.Equal(*resolved.FinishedAt) {
		t.Fatal("terminal retry changed completion", err)
	}
	if _, err := p.FinishSwitch(f.ctx, request, "committed", request.NextLeaf); err == nil {
		t.Fatal("terminal rollback reversed")
	}
	// The exact refused token remains usable after host recovery.
	assigned, err := f.repository.Register(f.ctx, r, f.issue)
	if err != nil {
		t.Fatal("enrollment did not recover after rollback", err)
	}
	c := device.Credential{TenantID: tenant, Hash: r.SecretHash}
	if _, err := store.Acknowledge(f.ctx, c, assigned.ID, overlap); err != nil {
		t.Fatal(err)
	}
	if _, err := p.BeginSwitch(f.ctx, other); err != nil {
		t.Fatal("new intent after rollback", err)
	}
	if _, err := p.FinishSwitch(f.ctx, other, "committed", other.NextLeaf); err != nil {
		t.Fatal("commit report failed", err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE relay_authority_switches SET phase='rolled_back',observed_leaf=previous_leaf WHERE id=$1`, other.ID); err == nil {
		t.Fatal("terminal history changed")
	}
	t.Log("Durable authority switch fenced enrollment and trust publication until an exact terminal host report; application reads/retries remained available")
}
