package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaycert"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func waitForRelayTrustTransaction(t *testing.T, f *enrollmentFixture, blocker *sql.Tx, result <-chan error, operation string) {
	t.Helper()
	var transaction string
	if err := blocker.QueryRowContext(f.ctx, `SELECT pg_current_xact_id()::text`).Scan(&transaction); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM pg_locks WHERE locktype='transactionid' AND NOT granted AND transactionid::text=$1`, transaction).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			t.Log(operation, "waited for the exact blocking transaction")
			return
		}
		select {
		case err := <-result:
			t.Fatal(operation, "returned before its lock wait was observed", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(operation, "did not wait for the exact blocking transaction")
}

func testRelayTrustHistory(t *testing.T, f *enrollmentFixture, web *sql.DB, tenant string) {
	t.Helper()
	publisher := &relaytrust.Publisher{Run: issuerSQLInput, ServerName: "relay.example.test"}
	if current, err := publisher.Current(f.ctx); err != nil || current != nil {
		t.Fatal("initial trust head", err)
	}
	if current, err := f.repository.CurrentRelayTrust(f.ctx, "relay.example.test"); err != nil || current != nil {
		t.Fatal("uninitialized application trust preflight", err)
	}
	old, err := relaycert.Create("relay.example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next, err := relaycert.Create("relay.example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices DISABLE TRIGGER devices_relay_trust_enrollment`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices ENABLE TRIGGER devices_relay_trust_enrollment`); err != nil {
				t.Error(err)
			}
		}()
		if f.repository.Health(f.ctx) == nil {
			t.Fatal("enrollment readiness accepted disabled trust fence")
		}
		if _, err := publisher.Publish(f.ctx, "", string(old.CA)); err == nil {
			t.Fatal("publication accepted disabled enrollment fence")
		}
	}()
	first, err := publisher.Publish(f.ctx, "", string(old.CA))
	if err != nil || first.Number != 1 {
		t.Fatal("initial publication", err)
	}
	retry, err := publisher.Publish(f.ctx, "", string(old.CA))
	if err != nil || retry.ID != first.ID {
		t.Fatal("lost publication reply changed identity", err)
	}
	if _, err := publisher.Publish(f.ctx, "", string(old.CA)+string(next.CA)); err == nil {
		t.Fatal("stale publication CAS accepted")
	}
	overlap, err := publisher.Publish(f.ctx, first.ID, string(next.CA)+string(old.CA))
	if err != nil || overlap.Number != 2 {
		t.Fatal("overlap publication", err)
	}
	if _, err := publisher.Publish(f.ctx, overlap.ID, string(next.CA)); err == nil {
		t.Fatal("old root retired without device acknowledgements")
	}
	r, _, _ := f.fresh(t, tenant)
	assigned, err := f.repository.Register(f.ctx, r, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	credential := device.Credential{TenantID: tenant, Hash: r.SecretHash}
	store := &RelayTrustStore{Enrollment: f.repository, ServerName: "relay.example.test"}
	current, err := store.Current(f.ctx, credential, assigned.ID)
	if err != nil || current.ID != overlap.ID {
		t.Fatal("authenticated current trust read", err)
	}
	if _, err := store.Acknowledge(f.ctx, credential, assigned.ID, first); !errors.Is(err, relaytrust.ErrChanged) {
		t.Fatal("stale trust report accepted", err)
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `CREATE FUNCTION fixture_relay_trust_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.relay_trust_applied' THEN RAISE EXCEPTION 'Fixture audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP FUNCTION fixture_relay_trust_audit_failure()`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := f.owner.ExecContext(f.ctx, `CREATE TRIGGER fixture_relay_trust_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fixture_relay_trust_audit_failure()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP TRIGGER fixture_relay_trust_audit_failure ON audit_log`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := store.Acknowledge(f.ctx, credential, assigned.ID, current); err != device.ErrUnavailable {
			t.Fatal("failed audit acknowledged trust", err)
		}
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM relay_trust_applications WHERE device_id=$1`, assigned.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("audit failure left applied receipt", err)
		}
	}()
	stamp, err := store.Acknowledge(f.ctx, credential, assigned.ID, current)
	if err != nil || stamp.IsZero() {
		t.Fatal("current trust application", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			received, err := store.Acknowledge(f.ctx, credential, assigned.ID, current)
			if err == nil && !received.Equal(stamp) {
				err = errors.New("receipt changed")
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent application retry", err)
		}
	}
	var reports, audits int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT (SELECT count(*) FROM relay_trust_applications WHERE device_id=$1),(SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.relay_trust_applied')`, assigned.ID).Scan(&reports, &audits); err != nil || reports != 1 || audits != 1 {
		t.Fatal("application retry duplicated audit/history", err)
	}
	wrong := credential
	wrong.Hash += "changed"
	if _, err := store.Acknowledge(f.ctx, wrong, assigned.ID, current); !errors.Is(err, device.ErrDenied) {
		t.Fatal("changed credential accepted", err)
	}
	wrong = credential
	wrong.TenantID = "00000000-0000-0000-0000-000000000000"
	if _, err := store.Current(f.ctx, wrong, assigned.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("cross tenant read accepted", err)
	}
	for _, db := range []*sql.DB{f.repository.DB, web} {
		if _, err := db.ExecContext(f.ctx, `SELECT * FROM relay_trust_generations`); err == nil {
			t.Fatal("raw trust history exposed")
		}
		if _, err := db.ExecContext(f.ctx, `SELECT publish_relay_trust(NULL,'relay.example.test','x','x','[]',now(),now())`); err == nil {
			t.Fatal("application role published trust")
		}
	}
	for _, role := range []string{"nethub_web", "nethub_authz", "nethub_issuer"} {
		for _, table := range []string{"relay_trust_generations", "relay_trust_head", "relay_trust_applications", "relay_authority_switches"} {
			var grants bool
			if err := f.owner.QueryRowContext(f.ctx, `SELECT has_table_privilege($1,$2,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege($1,$2,'SELECT,INSERT,UPDATE,REFERENCES')`, role, "public."+table).Scan(&grants); err != nil || grants {
				t.Fatal("raw relay trust grants", err)
			}
		}
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE relay_trust_generations SET server_name='changed' WHERE id=$1`, first.ID); err == nil {
		t.Fatal("trust generation mutated")
	}
	if _, err := f.owner.ExecContext(f.ctx, `DELETE FROM relay_trust_applications WHERE device_id=$1`, assigned.ID); err == nil {
		t.Fatal("application history deleted")
	}
	// A report waiting behind revocation must recheck the post-wait parent row.
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, assigned.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	waiting := make(chan error, 1)
	go func() { _, err := store.Acknowledge(ctx, credential, assigned.ID, current); waiting <- err }()
	waitForRelayTrustTransaction(t, f, blocker, waiting, "trust report during revocation")
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-waiting; !errors.Is(err, device.ErrDenied) {
		t.Fatal("revoked waiting report accepted", err)
	}
	// Enrollment cannot commit a new live device invisibly behind a publisher's
	// exclusive head lock. The newly committed device joins the retirement scan.
	headLock, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer headLock.Rollback()
	if _, err := headLock.ExecContext(f.ctx, `SELECT singleton FROM relay_trust_head WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	newRecord, _, _ := f.fresh(t, tenant)
	enrolled := make(chan error, 1)
	go func() { _, err := f.repository.Register(f.ctx, newRecord, f.issue); enrolled <- err }()
	waitForRelayTrustTransaction(t, f, headLock, enrolled, "enrollment during trust publication")
	f.unused(t, newRecord)
	// MVCC alone could hide an uncommitted token update. NOWAIT also proves
	// admission has not locked the one-use token while waiting on publication.
	var tokenAvailable bool
	if err := f.owner.QueryRowContext(f.ctx, `SELECT used_at IS NULL FROM enroll_tokens WHERE token_hash=$1 FOR UPDATE NOWAIT`, newRecord.TokenHash[:]).Scan(&tokenAvailable); err != nil || !tokenAvailable {
		t.Fatal("publication wait locked or consumed enrollment token", err)
	}
	t.Log("Enrollment token remained unused and immediately lockable during publication wait")
	if err := headLock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-enrolled; err != nil {
		t.Fatal("fenced enrollment failed after release", err)
	}
	// These are authenticated repository-level fixture reports, not proof that
	// any real appliance has installed the bundle. Cover every retained live row
	// so the genuine database retirement barrier can take its successful path.
	rows, err := f.owner.QueryContext(f.ctx, `SELECT id,tenant_id,device_secret_hash FROM devices WHERE NOT revoked ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	type liveDevice struct {
		id string
		c  device.Credential
	}
	var live []liveDevice
	for rows.Next() {
		var d liveDevice
		if err := rows.Scan(&d.id, &d.c.TenantID, &d.c.Hash); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		live = append(live, d)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(live) == 0 {
		t.Fatal("retirement fixture has no live devices")
	}
	request := relaytrust.SwitchRequest{ID: "4f90bb81-5258-4521-8010-ae6fe7bc5981", GenerationID: overlap.ID,
		PreviousRoot: first.Bundle().RootFingerprints()[0], PreviousLeaf: certificateDERFingerprint(t, old.Certificate),
		NextLeaf: certificateDERFingerprint(t, next.Certificate)}
	nextBundle, err := relaytrust.Parse(string(next.CA), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request.NextRoot = nextBundle.RootFingerprints()[0]
	if _, err := publisher.BeginSwitch(f.ctx, request); err == nil {
		t.Fatal("authority switch accepted unapplied device")
	}
	for _, d := range live {
		if _, err := store.Acknowledge(f.ctx, d.c, d.id, overlap); err != nil {
			t.Fatal("fixture current trust report", err)
		}
	}
	testRelayAuthoritySwitch(t, f, publisher, store, live[0].c, live[0].id, overlap, request, tenant, web)
	final, err := publisher.Publish(f.ctx, overlap.ID, string(next.CA))
	if err != nil || final.Number != 3 {
		t.Fatal("all-applied retirement refused", err)
	}
	if _, err := store.Acknowledge(f.ctx, live[0].c, live[0].id, overlap); !errors.Is(err, relaytrust.ErrChanged) {
		t.Fatal("previous head report accepted after retirement", err)
	}
	if retry, err := publisher.Publish(f.ctx, overlap.ID, string(next.CA)); err != nil || retry.ID != final.ID {
		t.Fatal("retirement reply loss duplicated generation", err)
	}
	// Exercise the production enrollment service after publication using the
	// existing response fields. The new assignment must carry the transaction's
	// current public trust, not the service's older bootstrap trust snapshot.
	data, err := os.ReadFile(filepath.Join(f.root, "examples/valid/enroll-response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap protocol.EnrollResponse
	if json.Unmarshal(data, &bootstrap) != nil {
		t.Fatal("bootstrap enrollment fixture")
	}
	expiredBootstrap, err := relaycert.Create("relay.example.test", time.Now().AddDate(-11, 0, 0))
	if err != nil {
		t.Fatal("expired bootstrap fixture", err)
	}
	bootstrap.RelayCAPEM = string(expiredBootstrap.CA)
	if _, err := relaytrust.Parse(bootstrap.RelayCAPEM, time.Now()); err == nil {
		t.Fatal("bootstrap fixture must independently fail current root validation")
	}
	service, err := device.New(f.repository, f.signer, device.RelayConfig{Address: bootstrap.ServerAddr, ServerName: "relay.example.test", Port: bootstrap.ServerPort, FRPToken: bootstrap.FRPToken, CAPEM: bootstrap.RelayCAPEM})
	if err != nil {
		t.Fatal(err)
	}
	if service.Health(f.ctx) != nil {
		t.Fatal("current database publication did not rescue expired bootstrap readiness")
	}
	func() {
		unused, token, _ := f.fresh(t, tenant)
		if _, err := f.owner.ExecContext(f.ctx, `GRANT SELECT ON relay_trust_generations TO nethub_authz`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `REVOKE SELECT ON relay_trust_generations FROM nethub_authz`); err != nil {
				t.Error(err)
			}
		}()
		if service.Health(f.ctx) == nil {
			t.Fatal("bootstrap recovery bypassed unsafe public-history grants")
		}
		request := f.input
		request.EnrollToken = token
		if response, err := service.Enroll(f.ctx, request, netip.MustParseAddr("192.0.2.19")); err == nil || response.DeviceSecret != "" {
			t.Fatal("unsafe trust readiness admitted or exposed credentials")
		}
		f.unused(t, unused)
	}()
	_, token, _ := f.fresh(t, tenant)
	input := f.input
	input.EnrollToken = token
	response, err := service.Enroll(f.ctx, input, netip.MustParseAddr("192.0.2.1"))
	if err != nil || response.RelayCAPEM != final.Bundle().PEM() || response.RelayCAPEM == bootstrap.RelayCAPEM || response.ServerName != "relay.example.test" {
		t.Fatal("enrollment delivered stale bootstrap trust", err)
	}
	bad, _, _ := f.fresh(t, tenant)
	bad.RelayServerName = "different.example.test"
	if _, err := f.repository.Register(f.ctx, bad, f.issue); err != device.ErrUnavailable {
		t.Fatal("different trust identity admitted enrollment", err)
	}
	f.unused(t, bad)
	trustService, err := device.NewRelayTrust(service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := trustService.Health(f.ctx); err != nil {
		t.Fatal("trust API schema readiness", err)
	}
	handler, err := device.NewHTTP(device.HTTPConfig{Origin: "https://console.example.com", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), RelayTrust: trustService}, service)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	for _, name := range []string{"common.schema.json", "relay-trust-settings-response.schema.json", "relay-trust-applied-response.schema.json"} {
		data, err := os.ReadFile(filepath.Join(f.root, "v1", name))
		if err != nil {
			t.Fatal(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(document.(map[string]any)["$id"].(string), document); err != nil {
			t.Fatal(err)
		}
	}
	postTrust := func(action string, value any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://console.example.com/api/v1/devices/relay-trust/"+action, bytes.NewReader(body))
		r.RemoteAddr = "192.0.2.2:12345"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+response.DeviceSecret)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code == 200 {
			schema, err := compiler.Compile("https://schemas.example.com/nethub/v1/relay-trust-" + action + "-response.schema.json")
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(w.Body.Bytes()))
			if err != nil || schema.Validate(value) != nil {
				t.Fatal("genuine trust HTTP output violates shared schema")
			}
		}
		return w
	}
	identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: response.DeviceID}
	w := postTrust("settings", identity)
	var settings protocol.RelayTrustSettings
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &settings) != nil || settings.Desired == nil || settings.Desired.ID != final.ID || settings.Desired.CAPEM != final.Bundle().PEM() {
		t.Fatal("genuine HTTP current trust delivery", w.Code)
	}
	report := protocol.RelayTrustAppliedRequest{Identity: identity, GenerationID: final.ID, Generation: final.Number, Fingerprint: final.Bundle().Fingerprint()}
	var acceptedAt string
	for range 2 {
		w = postTrust("applied", report)
		var accepted protocol.RelayTrustAppliedResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &accepted) != nil || accepted.Validate() != nil {
			t.Fatal("genuine HTTP trust acknowledgement", w.Code)
		}
		if acceptedAt != "" && acceptedAt != accepted.AcceptedAt {
			t.Fatal("HTTP trust retry changed receipt")
		}
		acceptedAt = accepted.AcceptedAt
	}
	report.GenerationID = overlap.ID
	report.Generation = overlap.Number
	report.Fingerprint = overlap.Bundle().Fingerprint()
	if w := postTrust("applied", report); w.Code != 409 {
		t.Fatal("HTTP stale trust did not request refresh", w.Code)
	}
	oldIdentity := identity
	oldIdentity.AgentProtocolVersion = "1.4.99"
	if w := postTrust("settings", oldIdentity); w.Code != 400 {
		t.Fatal("old HTTP trust peer accepted", w.Code)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if w := postTrust("settings", identity); w.Code != 401 {
		t.Fatal("revoked HTTP trust read accepted", w.Code)
	}
	testPublishedBootstrapRuntime(t, f, tenant, bootstrap, final)
	t.Log("Authenticated relay trust HTTP passed genuine database current delivery, exact report retry, stale-generation refresh, old-minor refusal and revoked-device denial")
	t.Log("Published relay trust enrollment passed current bundle delivery under the admission transaction and wrong-relay refusal before consuming the token; initialized startup/readiness use current publication despite expired bootstrap")
	t.Log("Durable relay trust history passed host-only publication CAS, overlap, unapplied retirement barrier, authenticated current-head reports, eight concurrent retries, private grants, immutable history and revoked waiting report refusal; no device delivery or root switch")
}
