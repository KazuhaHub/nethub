package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relaystate"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testRelayObservation(t *testing.T, f *enrollmentFixture, webRole *sql.DB, tenantA, tenantB string) {
	register := func(tenant string) device.Assignment {
		t.Helper()
		record, _, _ := f.fresh(t, tenant)
		value, err := f.repository.Register(f.ctx, record, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	a, b, revoked, wrongRoute := register(tenantA), register(tenantB), register(tenantA), register(tenantA)
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, revoked.ID); err != nil {
		t.Fatal(err)
	}
	snapshot := func(id string) string {
		t.Helper()
		var data string
		if err := f.owner.QueryRowContext(f.ctx, `SELECT (to_jsonb(d)-'last_seen_at')::text FROM devices d WHERE id=$1`, id).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := map[string]string{}
	for _, value := range []device.Assignment{a, b, revoked, wrongRoute} {
		before[value.ID] = snapshot(value.ID)
	}
	values := []relaystate.Observation{{DeviceID: a.ID, Subdomain: a.Subdomain}, {DeviceID: b.ID, Subdomain: b.Subdomain},
		{DeviceID: revoked.ID, Subdomain: revoked.Subdomain}, {DeviceID: wrongRoute.ID, Subdomain: "abcd9999"},
		{DeviceID: "ffffffff-ffff-4fff-bfff-ffffffffffff", Subdomain: "abcd1234"}}
	repository := &ObservationStore{DB: f.repository.DB}
	if err := repository.Observe(f.ctx, values); err != nil {
		t.Fatal("actual authz role could not record matching relay observations")
	}
	for _, value := range []device.Assignment{a, b, revoked, wrongRoute} {
		var recent, absent bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT coalesce(last_seen_at BETWEEN statement_timestamp()-interval '5 seconds' AND statement_timestamp(),false),last_seen_at IS NULL FROM devices WHERE id=$1`, value.ID).Scan(&recent, &absent); err != nil {
			t.Fatal(err)
		}
		expected := value.ID == a.ID || value.ID == b.ID
		if recent != expected || absent == expected || snapshot(value.ID) != before[value.ID] {
			t.Fatal("observation changed identity/configuration, refreshed a wrong route, or missed tenant scope")
		}
	}
	console := &ConsoleStore{AuthStore: AuthStore{DB: webRole, Tenant: tenantA}}
	page, err := console.Devices(f.ctx, a.OwnerID, web.DeviceQuery{Limit: 10})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != a.ID || !page.Items[0].Online {
		t.Fatal("matching observation did not reach the owner-scoped console online result")
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET last_seen_at=clock_timestamp()-interval '46 seconds' WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.Observe(f.ctx, nil); err != nil {
		t.Fatal(err)
	}
	page, err = console.Devices(f.ctx, a.OwnerID, web.DeviceQuery{Limit: 10})
	if err != nil || len(page.Items) != 1 || page.Items[0].Online {
		t.Fatal("empty/offline observation refreshed an expired console status")
	}
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, a.ID); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := repository.Observe(f.ctx, values[:2]); err != nil || time.Since(started) > time.Second {
		t.Fatal("display-only polling waited on a device authorization lock")
	}
	var stillOld bool
	if err := f.owner.QueryRowContext(f.ctx, `SELECT last_seen_at<statement_timestamp()-interval '45 seconds' FROM devices WHERE id=$1`, a.ID).Scan(&stillOld); err != nil || !stillOld {
		t.Fatal("locked device was not skipped")
	}
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := repository.Observe(f.ctx, values[:2]); err != nil {
		t.Fatal("observation did not recover after the device lock was released")
	}
	if err := (&ObservationStore{DB: webRole}).Observe(f.ctx, values[:1]); !errors.Is(err, relaystate.ErrStorage) {
		t.Fatal("console role acquired observation write authority")
	}
}
