package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relaystate"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

func testRelayAnomalies(t *testing.T, f *enrollmentFixture, webRole *sql.DB, tenant, otherTenant string) {
	t.Helper()
	repository := &ObservationStore{DB: f.repository.DB}
	register := func(t *testing.T, scope string) device.Assignment {
		t.Helper()
		request, _, _ := f.fresh(t, scope)
		assignment, err := f.repository.Register(f.ctx, request, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		return assignment
	}
	route := func(value device.Assignment, assigned string) relaystate.ObservedRoute {
		digest := sha256.Sum256([]byte(value.ID + "|" + assigned))
		return relaystate.ObservedRoute{DeviceID: value.ID, Subdomain: assigned, ProxyKey: hex.EncodeToString(digest[:])}
	}
	inspect := func(t *testing.T, routes []relaystate.ObservedRoute) []relaystate.Anomaly {
		t.Helper()
		findings, err := repository.Inspect(f.ctx, routes)
		if err != nil {
			t.Fatal(err)
		}
		return findings
	}
	confirm := func(t *testing.T, findings []relaystate.Anomaly, limit int) []relaystate.AnomalyConfirmation {
		t.Helper()
		now := time.Now()
		tracker, err := relaystate.NewAnomalyTracker(now, limit)
		if err != nil {
			t.Fatal(err)
		}
		var batch []relaystate.AnomalyConfirmation
		for index := 1; index <= 3; index++ {
			batch, err = tracker.Sample(now.Add(time.Duration(index)*15*time.Second), findings)
			if err != nil {
				t.Fatal(err)
			}
		}
		return batch
	}
	isRevoked := func(t *testing.T, id string) bool {
		t.Helper()
		var value bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT revoked FROM devices WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	countIncidents := func(t *testing.T, key string) int {
		t.Helper()
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM relay_anomaly_incidents WHERE proxy_key=$1`, key).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	project := func(t *testing.T, scope, actor string) string {
		t.Helper()
		tx, err := webRole.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, scope); err != nil {
			t.Fatal(err)
		}
		var value string
		if err = tx.QueryRowContext(f.ctx, `SELECT console_relay_alerts($1)::text`, actor).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}

	t.Run("classification_and_locked_recheck", func(t *testing.T) {
		a, b, normal := register(t, tenant), register(t, otherTenant), register(t, tenant)
		routes := []relaystate.ObservedRoute{route(a, "wrong001"), route(b, "wrong002"), route(normal, normal.Subdomain), {ProxyKey: strings.Repeat("a", 64)}}
		findings := inspect(t, routes)
		if len(findings) != 3 {
			t.Fatal("wrong classification count")
		}
		if findings[0].DeviceID != a.ID || findings[0].TenantID != tenant || findings[1].DeviceID != b.ID || findings[1].TenantID != otherTenant || findings[2].Kind != relaystate.UnknownProxy || findings[2].TenantID != "" || findings[2].DeviceID != "" {
			t.Fatal("relay data established guessed ownership")
		}
		if err := repository.Commit(f.ctx, routes, findings, nil); err != nil || isRevoked(t, a.ID) || countIncidents(t, routes[0].ProxyKey) != 0 {
			t.Fatal("unconfirmed finding caused an action", err)
		}
		// A normal online row held by another transaction must not block anomaly work.
		blocker, err := f.owner.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback()
		if _, err = blocker.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, normal.ID); err != nil {
			t.Fatal(err)
		}
		if err = repository.Commit(f.ctx, routes, findings, nil); err != nil {
			t.Fatal("normal online device was unnecessarily locked", err)
		}
		blocker.Rollback()
		one := []relaystate.ObservedRoute{routes[0]}
		expected := inspect(t, one)
		batch := confirm(t, expected, 3)
		if err = repository.Commit(f.ctx, one, expected, batch); err != nil || !isRevoked(t, a.ID) {
			t.Fatal("confirmed mismatch was not atomically revoked", err)
		}
		if err = repository.Commit(f.ctx, one, expected, batch); !errors.Is(err, relaystate.ErrAnomalyChanged) || countIncidents(t, one[0].ProxyKey) != 1 {
			t.Fatal("stale retry repeated the decision", err)
		}
		stale := inspect(t, []relaystate.ObservedRoute{routes[1]})
		staleBatch := confirm(t, stale, 3)
		if _, err = f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, b.ID); err != nil {
			t.Fatal(err)
		}
		if err = repository.Commit(f.ctx, []relaystate.ObservedRoute{routes[1]}, stale, staleBatch); !errors.Is(err, relaystate.ErrAnomalyChanged) || countIncidents(t, routes[1].ProxyKey) != 0 {
			t.Fatal("changed database row accepted a stale classification", err)
		}
	})

	t.Run("mass_alarm_does_not_escalate_after_restart", func(t *testing.T) {
		var values []device.Assignment
		var routes []relaystate.ObservedRoute
		for range 4 {
			value := register(t, tenant)
			values = append(values, value)
			routes = append(routes, route(value, "wrong003"))
		}
		findings := inspect(t, routes)
		batch := confirm(t, findings, 3)
		if len(batch) != 4 {
			t.Fatal("missing mass confirmation")
		}
		for _, item := range batch {
			if !item.AlarmOnly {
				t.Fatal("threshold failed")
			}
		}
		if err := repository.Commit(f.ctx, routes, findings, batch); err != nil {
			t.Fatal(err)
		}
		// A restarted tracker with a larger allowance cannot upgrade durable alarms.
		if err := repository.Commit(f.ctx, routes, inspect(t, routes), confirm(t, inspect(t, routes), 10)); err != nil {
			t.Fatal(err)
		}
		_, immutableError := f.owner.ExecContext(f.ctx, `UPDATE relay_anomaly_incidents SET response='revoked' WHERE proxy_key=$1`, routes[0].ProxyKey)
		var receiptError *pgconn.PgError
		if !errors.As(immutableError, &receiptError) || receiptError.Code != "23514" {
			t.Fatal("owner update bypassed immutable incident response", immutableError)
		}
		for index, value := range values {
			if isRevoked(t, value.ID) || countIncidents(t, routes[index].ProxyKey) != 1 {
				t.Fatal("persisted alarm escalated or duplicated")
			}
		}
	})

	t.Run("unknown_projection_and_cluster_alarm", func(t *testing.T) {
		value := register(t, tenant)
		foreign := register(t, otherTenant)
		if _, err := f.owner.ExecContext(f.ctx, `UPDATE users SET role='admin' WHERE id=$1`, value.OwnerID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET cluster_hint='review-cluster' WHERE id=$1`, value.ID); err != nil {
			t.Fatal(err)
		}
		routes := []relaystate.ObservedRoute{route(value, "wrong004"), {ProxyKey: strings.Repeat("b", 64)}}
		findings := inspect(t, routes)
		if err := repository.Commit(f.ctx, routes, findings, confirm(t, findings, 3)); err != nil || isRevoked(t, value.ID) {
			t.Fatal("cluster hint did not preserve manual review", err)
		}
		projection := project(t, tenant, value.OwnerID)
		if !strings.Contains(projection, "unknown_proxy") || !strings.Contains(projection, "alarm_only") || strings.Contains(projection, routes[1].ProxyKey) || strings.Contains(projection, foreign.ID) {
			t.Fatal("admin projection leaked a key/tenant or lost the alert")
		}
		if project(t, tenant, foreign.OwnerID) != "[]" {
			t.Fatal("foreign actor saw tenant alerts")
		}
		member := register(t, tenant)
		if project(t, tenant, member.OwnerID) != "[]" {
			t.Fatal("member saw admin alerts")
		}
		console := &ConsoleStore{AuthStore: AuthStore{DB: webRole, Tenant: tenant}}
		adminPage, err := console.Devices(f.ctx, value.OwnerID, web.DeviceQuery{Limit: 1})
		if err != nil || len(adminPage.RelayAlerts) != 2 {
			t.Fatal("admin inventory lost its bounded deployment alerts", err)
		}
		for _, alert := range adminPage.RelayAlerts {
			if !alert.Valid() {
				t.Fatal("invalid persisted alert projection")
			}
		}
		memberPage, err := console.Devices(f.ctx, member.OwnerID, web.DeviceQuery{Limit: 1})
		if err != nil || len(memberPage.RelayAlerts) != 0 {
			t.Fatal("inventory exposed admin alerts to a member", err)
		}
		if _, err := f.owner.ExecContext(f.ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, value.OwnerID); err != nil {
			t.Fatal(err)
		}
		if project(t, tenant, value.OwnerID) != "[]" {
			t.Fatal("disabled admin retained projection access")
		}
		if _, err := webRole.ExecContext(f.ctx, `SELECT id FROM relay_anomaly_incidents`); err == nil {
			t.Fatal("web role read raw incidents")
		}
		tx, err := f.repository.DB.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(f.ctx, `UPDATE relay_anomaly_incidents SET response='revoked' WHERE proxy_key=$1`, routes[0].ProxyKey); err == nil {
			t.Fatal("authz could rewrite immutable response")
		}
	})

	t.Run("busy_target_and_concurrent_receipt", func(t *testing.T) {
		value := register(t, tenant)
		if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, value.ID); err != nil {
			t.Fatal(err)
		}
		routes := []relaystate.ObservedRoute{route(value, value.Subdomain)}
		findings := inspect(t, routes)
		batch := confirm(t, findings, 3)
		blocker, err := f.owner.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback()
		if _, err = blocker.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, value.ID); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if err = repository.Commit(f.ctx, routes, findings, batch); !errors.Is(err, relaystate.ErrStorage) || time.Since(started) > time.Second {
			t.Fatal("busy anomaly target waited or succeeded", err)
		}
		blocker.Rollback()
		var wg sync.WaitGroup
		failures := make(chan error, 8)
		for range 8 {
			wg.Go(func() {
				var err error
				for attempt := 0; attempt < 20; attempt++ {
					err = repository.Commit(f.ctx, routes, findings, batch)
					if err == nil {
						break
					}
					if !errors.Is(err, relaystate.ErrStorage) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				failures <- err
			})
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal("concurrent exact retry failed", err)
			}
		}
		if countIncidents(t, routes[0].ProxyKey) != 1 {
			t.Fatal("concurrent receipt duplicated")
		}
		var audits int
		if err = f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE action='relay.anomaly_decisions' AND payload->'decisions' @> jsonb_build_array(jsonb_build_object('device_id',$1::text))`, value.ID).Scan(&audits); err != nil || audits != 1 {
			t.Fatal("concurrent audit duplicated", err)
		}
	})

	t.Run("audit_failure_rolls_back_action_and_receipt", func(t *testing.T) {
		value := register(t, tenant)
		routes := []relaystate.ObservedRoute{route(value, "wrong005")}
		findings := inspect(t, routes)
		batch := confirm(t, findings, 3)
		if _, err := f.owner.ExecContext(f.ctx, `CREATE FUNCTION reject_anomaly_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='relay.anomaly_decisions' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_anomaly_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_anomaly_audit()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `DROP TRIGGER IF EXISTS reject_anomaly_audit ON audit_log; DROP FUNCTION IF EXISTS reject_anomaly_audit()`); err != nil {
				t.Error(err)
			}
		}()
		if err := repository.Commit(f.ctx, routes, findings, batch); err == nil || isRevoked(t, value.ID) || countIncidents(t, routes[0].ProxyKey) != 0 {
			t.Fatal("audit failure left a committed mutation", err)
		}
	})
	var raw string
	if err := f.owner.QueryRowContext(f.ctx, `SELECT coalesce(jsonb_agg(payload)::text,'[]') FROM audit_log WHERE action='relay.anomaly_decisions'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var audit []json.RawMessage
	if json.Unmarshal([]byte(raw), &audit) != nil || strings.Contains(raw, strings.Repeat("b", 64)) {
		t.Fatal("unknown route digest escaped into audit")
	}
	t.Log("Relay anomalies passed scoped classification, locked recheck, no unconfirmed action, immutable mass alarms after restart, cluster review, private admin projection, busy-target skip, concurrent idempotence and audit rollback")
}
