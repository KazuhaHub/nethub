package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
	"github.com/jackc/pgx/v5/pgconn"
)

func testDeviceRotation(t *testing.T, ctx context.Context, owner, authz, web *sql.DB) {
	f := newEnrollmentFixture(t, ctx, owner, authz)
	var tenant string
	if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('Rotation') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	bound, err := os.ReadFile(filepath.Join(f.root, "examples/valid/enroll-bound-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := protocol.DecodeEnroll(bytes.NewReader(bound))
	if err != nil {
		t.Fatal(err)
	}
	fresh := func(t *testing.T) protocol.EnrollResponse {
		t.Helper()
		_, token, _ := f.fresh(t, tenant)
		r := input
		r.EnrollToken = token
		value, err := f.service.Enroll(ctx, r, netip.MustParseAddr("192.0.2.151"))
		if err != nil {
			t.Fatal("rotation enrollment fixture failed")
		}
		return value
	}
	secret := func(value byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	request := func(value protocol.EnrollResponse, op, candidate string) protocol.RotateRequest {
		return protocol.RotateRequest{Identity: protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: value.DeviceID},
			OperationID: op, ReplacementSecret: candidate}
	}
	var log bytes.Buffer
	handler, err := device.NewHTTP(device.HTTPConfig{Origin: "https://console.example.com", Logger: slog.New(slog.NewJSONHandler(&log, nil))}, f.service)
	if err != nil {
		t.Fatal(err)
	}
	post := func(r protocol.RotateRequest, bearer string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(r)
		req := httptest.NewRequest(http.MethodPost, "https://console.example.com/api/v1/devices/rotate", bytes.NewReader(data))
		req.RemoteAddr = "192.0.2.152:12345"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) protocol.RotateResponse {
		t.Helper()
		var r protocol.RotateResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &r) != nil {
			t.Fatalf("rotation response status=%d", w.Code)
		}
		return r
	}
	counts := func(t *testing.T, id string, want int) {
		t.Helper()
		var operations, audits int
		if err := owner.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM device_rotations WHERE device_id=$1),
 (SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.rotated')`, id).Scan(&operations, &audits); err != nil || operations != want || audits != want {
			t.Fatal("rotation operation/audit count mismatch")
		}
	}
	snapshot := func(t *testing.T, id string) string {
		t.Helper()
		var value string
		if err := owner.QueryRowContext(ctx, `SELECT jsonb_build_array(id,tenant_id,owner_user_id,subdomain,gui_public_key,enrolled_at)::text FROM devices WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	op1, op2 := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	t.Run("commit_recovery_and_stable_identity", func(t *testing.T) {
		before := fresh(t)
		identity := snapshot(t, before.DeviceID)
		r := request(before, op1, secret(71))
		first := decode(t, post(r, before.DeviceSecret))
		if first.DeviceID != before.DeviceID || first.Subdomain != before.Subdomain || first.DeviceSecret != r.ReplacementSecret || first.OperationID != op1 || first.DomainClaim == before.DomainClaim {
			t.Fatal("rotation changed identity or lost candidate/claim binding")
		}
		oldClaim, _ := f.signer.Verify(before.DomainClaim)
		newClaim, err := f.signer.Verify(first.DomainClaim)
		if err != nil || !errors.Is((&RelayStore{DB: authz}).Authorize(ctx, oldClaim), relayhook.ErrDenied) || (&RelayStore{DB: authz}).Authorize(ctx, newClaim) != nil {
			t.Fatal("actual relay admission did not replace the old claim")
		}
		cache, err := relayhook.NewRevocationCache(&RelayStore{DB: authz}, slog.New(slog.NewJSONHandler(&log, nil)))
		if err != nil || cache.Refresh(ctx) != nil || !errors.Is(cache.AuthorizePing(oldClaim), relayhook.ErrDenied) || cache.AuthorizePing(newClaim) != nil {
			t.Fatal("actual SQL rotation floor did not reject old heartbeat claims")
		}
		oldTime, _ := time.Parse("2006-01-02T15:04:05.000000Z", oldClaim.IssuedAt)
		newTime, _ := time.Parse("2006-01-02T15:04:05.000000Z", newClaim.IssuedAt)
		if !newTime.After(oldTime) || snapshot(t, before.DeviceID) != identity {
			t.Fatal("claim clock or immutable device/GUI identity changed incorrectly")
		}
		if w := post(r, before.DeviceSecret); w.Code != 401 || strings.Contains(w.Body.String(), r.ReplacementSecret) {
			t.Fatal("old credential accepted or failure disclosed the candidate")
		}
		recovered := decode(t, post(r, r.ReplacementSecret))
		if recovered != first {
			t.Fatal("response-loss recovery changed the assignment")
		}
		counts(t, before.DeviceID, 1)
		conflict := r
		conflict.ReplacementSecret = secret(72)
		if post(conflict, r.ReplacementSecret).Code != 401 {
			t.Fatal("existing operation accepted another candidate")
		}
		unrecorded := r
		unrecorded.OperationID = op2
		if post(unrecorded, r.ReplacementSecret).Code != 401 {
			t.Fatal("current credential created an unrecorded no-op rotation")
		}
		next := request(before, op2, secret(73))
		decode(t, post(next, r.ReplacementSecret))
		if post(r, r.ReplacementSecret).Code != 401 || post(r, next.ReplacementSecret).Code != 401 {
			t.Fatal("superseded operation was resurrected")
		}
		counts(t, before.DeviceID, 2)
		if strings.Contains(log.String(), before.DeviceSecret) || strings.Contains(log.String(), r.ReplacementSecret) {
			t.Fatal("device credentials entered diagnostics")
		}
	})
	t.Run("concurrent_candidates_have_one_winner", func(t *testing.T) {
		before := fresh(t)
		requests := []protocol.RotateRequest{request(before, op1, secret(74)), request(before, op2, secret(75))}
		responses := make([]*httptest.ResponseRecorder, 2)
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range requests {
			workers.Go(func() { <-start; responses[i] = post(requests[i], before.DeviceSecret) })
		}
		close(start)
		workers.Wait()
		winner := -1
		for i, response := range responses {
			if response.Code == 200 {
				if winner != -1 {
					t.Fatal("concurrent candidates both committed")
				}
				winner = i
			} else if response.Code != 401 {
				t.Fatalf("unexpected concurrent rotation status=%d", response.Code)
			}
		}
		if winner == -1 {
			t.Fatal("no concurrent candidate committed")
		}
		decode(t, post(requests[winner], requests[winner].ReplacementSecret))
		counts(t, before.DeviceID, 1)
	})
	t.Run("audit_and_signing_failure_roll_back", func(t *testing.T) {
		before := fresh(t)
		r := request(before, op1, secret(76))
		if _, err := owner.ExecContext(ctx, `CREATE FUNCTION reject_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.rotated' THEN RAISE EXCEPTION 'fixture rotation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_rotation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_rotation_audit()`); err != nil {
			t.Fatal(err)
		}
		func() {
			defer owner.ExecContext(ctx, `DROP TRIGGER reject_rotation_audit ON audit_log; DROP FUNCTION reject_rotation_audit()`)
			if post(r, before.DeviceSecret).Code != 503 {
				t.Fatal("audit failure returned success")
			}
			counts(t, before.DeviceID, 0)
		}()
		credential, err := f.repository.DeviceCredential(ctx, before.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		if valid, err := auth.VerifyPassword(credential.Hash, before.DeviceSecret); err != nil || !valid {
			t.Fatal("failed audit changed the current credential")
		}
		hash, err := auth.HashPassword(r.ReplacementSecret)
		if err != nil {
			t.Fatal(err)
		}
		record := device.RotationRecord{Identity: r.Identity, OperationID: op1, CandidateDigest: sha256.Sum256([]byte(r.ReplacementSecret)), SecretHash: hash,
			RelayServerName: before.ServerName, SourceIP: netip.MustParseAddr("192.0.2.154")}
		if _, err := f.repository.RotateDevice(ctx, credential, record, func(device.Assignment) (string, error) { return "", errors.New("fixture signing failure") }); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("signing failure returned success")
		}
		counts(t, before.DeviceID, 0)
		decode(t, post(r, before.DeviceSecret))
	})
	t.Run("revocation_tenant_roles_and_immutable_history", func(t *testing.T) {
		before := fresh(t)
		r := request(before, op1, secret(77))
		decode(t, post(r, before.DeviceSecret))
		_, err := web.ExecContext(ctx, `SELECT candidate_digest FROM device_rotations`)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("Web can read rotation credential commitments")
		}
		tx, err := authz.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id','ffffffff-ffff-ffff-ffff-ffffffffffff',true)`); err != nil {
				t.Fatal(err)
			}
			var visible int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM device_rotations WHERE device_id=$1`, before.DeviceID).Scan(&visible); err != nil || visible != 0 {
				t.Fatal("rotation history escaped forced tenant RLS")
			}
		}()
		credential, err := f.repository.DeviceCredential(ctx, before.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		forged := credential
		forged.TenantID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		record := device.RotationRecord{Identity: r.Identity, OperationID: op1, CandidateDigest: sha256.Sum256([]byte(r.ReplacementSecret)),
			SecretHash: credential.Hash, CandidateIsCurrent: true, RelayServerName: before.ServerName, SourceIP: netip.MustParseAddr("192.0.2.155")}
		if _, err := f.repository.RotateDevice(ctx, forged, record, f.issue); !errors.Is(err, device.ErrDenied) {
			t.Fatal("forged tenant recovered a rotation")
		}
		for _, query := range []string{`UPDATE device_rotations SET issued_at=clock_timestamp() WHERE device_id=$1`, `DELETE FROM device_rotations WHERE device_id=$1`} {
			_, err := owner.ExecContext(ctx, query, before.DeviceID)
			var immutable *pgconn.PgError
			if !errors.As(err, &immutable) || immutable.Code != "P0001" {
				t.Fatal("rotation history was mutable")
			}
		}
		if _, err := owner.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, before.DeviceID); err != nil {
			t.Fatal(err)
		}
		if post(r, r.ReplacementSecret).Code != 401 {
			t.Fatal("revoked device recovered a credential rotation")
		}
		counts(t, before.DeviceID, 1)
	})
	t.Run("database_claim_clock_stays_monotonic", func(t *testing.T) {
		before := fresh(t)
		var previous time.Time
		if err := owner.QueryRowContext(ctx, `UPDATE devices SET domain_claim_issued_at=clock_timestamp()+interval '1 minute'
 WHERE id=$1 RETURNING domain_claim_issued_at`, before.DeviceID).Scan(&previous); err != nil {
			t.Fatal(err)
		}
		r := request(before, op1, secret(78))
		result := decode(t, post(r, before.DeviceSecret))
		payload, err := f.signer.Verify(result.DomainClaim)
		issued, timeErr := time.Parse("2006-01-02T15:04:05.000000Z", payload.IssuedAt)
		if err != nil || timeErr != nil || !issued.Equal(previous.Add(time.Microsecond)) {
			t.Fatal("rotation did not advance the exact database timestamp after a clock regression")
		}
		counts(t, before.DeviceID, 1)
	})
	t.Log("Rotation SQL verified atomic credential/claim/audit publication, candidate-authenticated response-loss recovery, stale credential and claim refusal, stable identity, concurrent single winner, audit/signing rollback, tenant/Web boundaries and immutable revoked history")
}
