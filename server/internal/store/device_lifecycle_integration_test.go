package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

func testDeviceLifecycle(t *testing.T, ctx context.Context, owner, authz, web *sql.DB) {
	f := newEnrollmentFixture(t, ctx, owner, authz)
	var tenant string
	if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Lifecycle') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	_, token, actor := f.fresh(t, tenant)
	input := f.input
	input.EnrollToken = token
	assignment, err := f.service.Enroll(ctx, input, netip.MustParseAddr("192.0.2.131"))
	if err != nil {
		t.Fatal(err)
	}
	id := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: assignment.DeviceID}
	report := protocol.StatusRequest{Identity: id, PlatformVersion: "fixture-current", AgentVersion: "0.0.4", ServiceState: "running"}
	handler, err := device.NewHTTP(device.HTTPConfig{Origin: "https://console.example.com", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}, f.service)
	if err != nil {
		t.Fatal(err)
	}
	post := func(path, secret string, value any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(value)
		r := httptest.NewRequest(http.MethodPost, "https://console.example.com/api/v1/devices/"+path, bytes.NewReader(data))
		r.RemoteAddr = "192.0.2.132:12345"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	t.Run("credential_and_role_scope", func(t *testing.T) {
		wrong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32))
		if post("status", wrong, report).Code != 401 {
			t.Fatal("wrong credential accepted")
		}
		unknown := report
		unknown.DeviceID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		if post("status", assignment.DeviceSecret, unknown).Code != 401 {
			t.Fatal("another identity accepted")
		}
		if _, err := (&EnrollmentStore{DB: web}).DeviceCredential(ctx, id.DeviceID); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("web can read device credential")
		}
		credential, err := f.repository.DeviceCredential(ctx, id.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		credential.TenantID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		if _, err = f.repository.ReportDevice(ctx, credential, report); !errors.Is(err, device.ErrDenied) {
			t.Fatal("forged tenant accepted")
		}
	})
	t.Run("health_does_not_claim_relay_liveness", func(t *testing.T) {
		w := post("status", assignment.DeviceSecret, report)
		if w.Code != 200 {
			t.Fatalf("status=%d", w.Code)
		}
		var state string
		var observed sql.NullTime
		if err := owner.QueryRowContext(ctx, `SELECT service_state,last_seen_at FROM devices WHERE id=$1 AND last_report_at IS NOT NULL AND platform_version='fixture-current'`, id.DeviceID).Scan(&state, &observed); err != nil || state != "running" || observed.Valid {
			t.Fatal("health changed online state or was not saved")
		}
	})
	t.Run("audit_failure_rolls_back_revocation", func(t *testing.T) {
		_, err := owner.ExecContext(ctx, `CREATE FUNCTION reject_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.unenrolled' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_lifecycle_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_audit()`)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.ExecContext(ctx, `DROP TRIGGER reject_lifecycle_audit ON audit_log; DROP FUNCTION reject_lifecycle_audit()`)
		if post("unenroll", assignment.DeviceSecret, id).Code != 503 {
			t.Fatal("audit failure accepted")
		}
		var revoked bool
		if err := owner.QueryRowContext(ctx, `SELECT revoked FROM devices WHERE id=$1`, id.DeviceID).Scan(&revoked); err != nil || revoked {
			t.Fatal("failed audit committed revocation")
		}
	})
	t.Run("concurrent_unenroll_is_one_way_and_idempotent", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				if w := post("unenroll", assignment.DeviceSecret, id); w.Code != 200 {
					t.Errorf("unenroll status=%d", w.Code)
				}
			})
		}
		wg.Wait()
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE action='device.unenrolled' AND target_device_id=$1`, id.DeviceID).Scan(&count); err != nil || count != 1 {
			t.Fatal("duplicate or missing audit")
		}
		w := post("status", assignment.DeviceSecret, report)
		var result protocol.StatusResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Revoked {
			t.Fatal("revocation not returned")
		}
		if _, err := owner.ExecContext(ctx, `UPDATE devices SET revoked=false WHERE id=$1`, id.DeviceID); err == nil {
			t.Fatal("revocation reversed")
		}
		if _, err := owner.ExecContext(ctx, `INSERT INTO devices(tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version) VALUES($1,$2,'opnsense','fixture-hash',$3,'1.0.0')`, tenant, actor, assignment.Subdomain); err != nil {
			t.Fatal("revoked routing name not released")
		}
		claim, err := f.signer.Verify(assignment.DomainClaim)
		if err != nil || !errors.Is((&RelayStore{DB: authz}).Authorize(ctx, claim), relayhook.ErrDenied) {
			t.Fatal("old claim authorized a reused routing name")
		}
	})
	t.Run("rotated_credential_rechecked_under_write_lock", func(t *testing.T) {
		credential, err := f.repository.DeviceCredential(ctx, id.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = owner.ExecContext(ctx, `UPDATE devices SET device_secret_hash='replacement-fixture' WHERE id=$1`, id.DeviceID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.repository.ReportDevice(ctx, credential, report); !errors.Is(err, device.ErrDenied) {
			t.Fatal("stale credential accepted")
		}
	})
}
