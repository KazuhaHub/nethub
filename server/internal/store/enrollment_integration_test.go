package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type enrollmentFixture struct {
	ctx        context.Context
	owner      *sql.DB
	repository *EnrollmentStore
	service    *device.Service
	signer     *claim.Keyring
	input      protocol.EnrollRequest
	root, hash string
	sequence   int
	issue      func(device.Assignment) (string, error)
}

func newEnrollmentFixture(t *testing.T, ctx context.Context, owner, authz *sql.DB) *enrollmentFixture {
	t.Helper()
	f := &enrollmentFixture{ctx: ctx, owner: owner, repository: &EnrollmentStore{DB: authz}, root: os.Getenv("NETHUB_PROTOCOL_FIXTURES")}
	if f.root == "" {
		t.Fatal("the genuine database harness must copy the shared protocol fixtures")
	}
	requestData, err := os.ReadFile(filepath.Join(f.root, "examples/valid/enroll-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.input, err = protocol.DecodeEnroll(bytes.NewReader(requestData))
	if err != nil {
		t.Fatal(err)
	}
	responseData, err := os.ReadFile(filepath.Join(f.root, "examples/valid/enroll-response.json"))
	var response protocol.EnrollResponse
	if err != nil || json.Unmarshal(responseData, &response) != nil {
		t.Fatal("shared enrollment response fixture unavailable")
	}
	f.signer, err = claim.New("integration", map[string][]byte{"integration": bytes.Repeat([]byte{17}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = device.New(f.repository, f.signer, device.RelayConfig{
		Address: response.ServerAddr, ServerName: response.ServerName, Port: response.ServerPort,
		FRPToken: response.FRPToken, CAPEM: response.RelayCAPEM})
	if err != nil {
		t.Fatal(err)
	}
	f.hash, err = auth.HashPassword("public-integration-secret-fixture")
	if err != nil {
		t.Fatal(err)
	}
	f.issue = func(value device.Assignment) (string, error) {
		return f.signer.Issue(value.ID, value.Subdomain, value.TenantID, value.IssuedAt)
	}
	return f
}

func (f *enrollmentFixture) fresh(t *testing.T, tenant string) (device.Registration, string, string) {
	t.Helper()
	f.sequence++
	var actor string
	if err := f.owner.QueryRowContext(f.ctx, `INSERT INTO users(tenant_id,email,role) VALUES($1,$2,'member') RETURNING id`, tenant, fmt.Sprintf("device-enroll-%d@example.com", f.sequence)).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw[:])
	if _, err := f.owner.ExecContext(f.ctx, `INSERT INTO enroll_tokens(tenant_id,created_by_user_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,clock_timestamp()-interval '2 minutes',clock_timestamp()+interval '10 minutes')`, tenant, actor, digest[:]); err != nil {
		t.Fatal(err)
	}
	return device.Registration{TokenHash: digest, SecretHash: f.hash,
			Candidates: []string{fmt.Sprintf("%08x", f.sequence)}, SourceIP: netip.MustParseAddr("192.0.2.1"),
			Metadata: device.Metadata{ProtocolVersion: protocol.Version, Platform: f.input.Platform,
				PlatformVersion: f.input.PlatformVersion, AgentVersion: f.input.AgentVersion,
				Hostname: f.input.Hostname, Capabilities: append([]string(nil), f.input.Capabilities...)}},
		base64.RawURLEncoding.EncodeToString(raw[:]), actor
}

func (f *enrollmentFixture) unused(t *testing.T, record device.Registration) {
	t.Helper()
	var unused bool
	if err := f.owner.QueryRowContext(f.ctx, `SELECT used_at IS NULL FROM enroll_tokens WHERE token_hash=$1`, record.TokenHash[:]).Scan(&unused); err != nil || !unused {
		t.Fatalf("failed admission consumed the token: %v", err)
	}
}

func (f *enrollmentFixture) noDevice(t *testing.T, name string) {
	t.Helper()
	var count int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM devices WHERE subdomain=$1`, name).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed admission persisted a device: %v", err)
	}
}

func (f *enrollmentFixture) validateResponse(t *testing.T, encoded []byte) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	for _, name := range []string{"common.schema.json", "enroll-response.schema.json"} {
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
	schema, err := compiler.Compile("https://schemas.example.com/nethub/v1/enroll-response.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil || schema.Validate(instance) != nil {
		t.Fatal("genuine service output violates the shared schema")
	}
}

func (f *enrollmentFixture) post(t *testing.T, input protocol.EnrollRequest) (int, []byte) {
	t.Helper()
	handler, err := device.NewHTTP(device.HTTPConfig{Origin: "https://console.example.com",
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}, f.service)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, server.URL+"/api/v1/devices/enroll", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example.com"
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("enrollment HTTP request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
	if err != nil || len(body) > protocol.MaxBodyBytes || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("enrollment HTTP response is unreadable, oversized or cacheable")
	}
	return response.StatusCode, body
}

func testAtomicEnrollment(t *testing.T, ctx context.Context, owner, authz, webRole *sql.DB, tenantA, tenantB string) {
	f := newEnrollmentFixture(t, ctx, owner, authz)
	t.Run("readiness_requires_authz_role", func(t *testing.T) {
		if err := f.service.Health(ctx); err != nil {
			t.Fatal("migrated authz role did not pass readiness")
		}
		if err := (&EnrollmentStore{DB: owner}).Health(ctx); err == nil {
			t.Fatal("owner role accepted as authorization runtime")
		}
	})
	t.Run("compiled_authz_process", func(t *testing.T) { testAuthzRuntime(t, f, tenantA) })
	t.Run("http_result_matches_schema_and_database_identity", func(t *testing.T) {
		_, token, actor := f.fresh(t, tenantB)
		request := f.input
		request.EnrollToken, request.Platform, request.ClusterHint = token, "openwrt", true
		status, body := f.post(t, request)
		var response protocol.EnrollResponse
		if status != http.StatusCreated || json.Unmarshal(body, &response) != nil {
			t.Fatal("HTTP enrollment did not return a successful protocol response")
		}
		var tenant, storedActor, hash, platform, cluster string
		var issued time.Time
		var capabilities bool
		if err := owner.QueryRowContext(ctx, `SELECT tenant_id,owner_user_id,device_secret_hash,platform,cluster_hint,domain_claim_issued_at,capabilities=ARRAY['remote.web'] FROM devices WHERE id=$1`, response.DeviceID).Scan(&tenant, &storedActor, &hash, &platform, &cluster, &issued, &capabilities); err != nil {
			t.Fatal(err)
		}
		if tenant != tenantB || storedActor != actor || platform != "openwrt" || cluster != "cluster member" || !capabilities {
			t.Fatal("device identity or metadata did not come from the correct sources")
		}
		if match, err := auth.VerifyPassword(hash, response.DeviceSecret); err != nil || !match || hash == response.DeviceSecret {
			t.Fatal("database does not contain only the device secret hash")
		}
		payload, err := f.signer.Verify(response.DomainClaim)
		if err != nil || payload.TenantID != tenant || payload.DeviceID != response.DeviceID || payload.Subdomain != response.Subdomain || payload.IssuedAt != issued.UTC().Format("2006-01-02T15:04:05.000000Z") {
			t.Fatal("signed identity does not exactly match the committed row")
		}
		f.validateResponse(t, body)
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND actor_id=$2 AND action='device.enrolled' AND target_device_id=$3 AND NOT (payload ? 'domain_claim')`, tenantB, actor, response.DeviceID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("success audit is missing or contains credential fields: %v", err)
		}
		if status, body := f.post(t, request); status != 401 || bytes.Contains(body, []byte("device_secret")) || !bytes.Contains(body, []byte("enrollment_failed")) {
			t.Fatal("replayed token did not return the generic HTTP denial")
		}
	})
	t.Run("version_rejected_before_consumption", func(t *testing.T) {
		record, token, _ := f.fresh(t, tenantA)
		request := f.input
		request.EnrollToken, request.AgentProtocolVersion = token, "2.0.0"
		if status, body := f.post(t, request); status != 400 || !bytes.Contains(body, []byte("incompatible_protocol")) {
			t.Fatal("incompatible protocol was not rejected at the HTTP boundary")
		}
		f.unused(t, record)
	})
	t.Run("single_winner_with_atomic_audit", func(t *testing.T) {
		record, _, actor := f.fresh(t, tenantA)
		var winners atomic.Int32
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				if _, err := f.repository.Register(ctx, record, f.issue); err == nil {
					winners.Add(1)
				} else if !errors.Is(err, device.ErrDenied) {
					t.Error("concurrent admission failed for an unexpected reason")
				}
			})
		}
		workers.Wait()
		if winners.Load() != 1 {
			t.Fatalf("expected one winner, got %d", winners.Load())
		}
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE actor_id=$1 AND action='device.enrolled'`, actor).Scan(&count); err != nil || count != 1 {
			t.Fatalf("concurrent admission did not append exactly one event: %v", err)
		}
	})
	t.Run("invalid_expired_and_disabled_are_indistinguishable", func(t *testing.T) {
		for _, kind := range []string{"unknown", "expired", "disabled", "not-yet-valid"} {
			record, _, actor := f.fresh(t, tenantA)
			switch kind {
			case "unknown":
				record.TokenHash = sha256.Sum256([]byte("unknown public test token"))
			case "expired":
				_, err := owner.ExecContext(ctx, `UPDATE enroll_tokens SET expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`, record.TokenHash[:])
				if err != nil {
					t.Fatal(err)
				}
			case "disabled":
				_, err := owner.ExecContext(ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, actor)
				if err != nil {
					t.Fatal(err)
				}
			case "not-yet-valid":
				_, err := owner.ExecContext(ctx, `UPDATE enroll_tokens SET created_at=clock_timestamp()+interval '1 minute',expires_at=clock_timestamp()+interval '5 minutes' WHERE token_hash=$1`, record.TokenHash[:])
				if err != nil {
					t.Fatal(err)
				}
			}
			if assigned, err := f.repository.Register(ctx, record, f.issue); !errors.Is(err, device.ErrDenied) || assigned.ID != "" {
				t.Fatalf("invalid enrollment differs from generic denial: %s", kind)
			}
			f.noDevice(t, record.Candidates[0])
		}
	})
	t.Run("signing_failure_rolls_back_token_and_device", func(t *testing.T) {
		record, _, _ := f.fresh(t, tenantA)
		if _, err := f.repository.Register(ctx, record, func(device.Assignment) (string, error) { return "", errors.New("private signing failure") }); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("signing failure was not rejected")
		}
		f.unused(t, record)
		f.noDevice(t, record.Candidates[0])
		if _, err := f.repository.Register(ctx, record, f.issue); err != nil {
			t.Fatal("rolled-back enrollment could not reuse its unconsumed token")
		}
	})
	t.Run("subdomain_conflict_retries_without_cross_tenant_leak", func(t *testing.T) {
		occupied, _, _ := f.fresh(t, tenantB)
		if _, err := f.repository.Register(ctx, occupied, f.issue); err != nil {
			t.Fatal(err)
		}
		record, _, _ := f.fresh(t, tenantA)
		wanted := record.Candidates[0]
		record.Candidates = []string{occupied.Candidates[0], wanted}
		assigned, err := f.repository.Register(ctx, record, f.issue)
		if err != nil || assigned.Subdomain != wanted || assigned.TenantID != tenantA {
			t.Fatal("unique-name retry changed ownership or failed")
		}
		exhausted, _, _ := f.fresh(t, tenantA)
		freshName := exhausted.Candidates[0]
		exhausted.Candidates = []string{wanted}
		if _, err := f.repository.Register(ctx, exhausted, f.issue); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("exhausted conflict was not rejected")
		}
		f.unused(t, exhausted)
		exhausted.Candidates = []string{freshName}
		if _, err := f.repository.Register(ctx, exhausted, f.issue); err != nil {
			t.Fatal("conflict rollback consumed the token")
		}
	})
	t.Run("audit_failure_rolls_back_enrollment", func(t *testing.T) {
		for _, query := range []string{
			`CREATE FUNCTION test_enrollment_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='device.enrolled' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$`,
			`CREATE TRIGGER test_enrollment_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_enrollment_audit_failure()`,
		} {
			if _, err := owner.ExecContext(ctx, query); err != nil {
				t.Fatal(err)
			}
		}
		defer owner.ExecContext(ctx, `DROP FUNCTION IF EXISTS test_enrollment_audit_failure() CASCADE`)
		record, _, _ := f.fresh(t, tenantA)
		if _, err := f.repository.Register(ctx, record, f.issue); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("audit failure was not rejected")
		}
		f.unused(t, record)
		f.noDevice(t, record.Candidates[0])
		if _, err := owner.ExecContext(ctx, `DROP TRIGGER test_enrollment_audit_failure ON audit_log`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repository.Register(ctx, record, f.issue); err != nil {
			t.Fatal("audit rollback consumed the token")
		}
	})
	t.Run("eligibility_is_rechecked_after_row_locks", func(t *testing.T) {
		for _, kind := range []string{"disable-user", "expiry-user-lock", "expiry-token-lock"} {
			t.Run(kind, func(t *testing.T) { f.lockRace(t, kind, tenantA) })
		}
	})
	t.Run("relay_identity_and_revocation", func(t *testing.T) { testRelayAuthorization(t, f, tenantA, tenantB) })
	t.Run("relay_observation", func(t *testing.T) { testRelayObservation(t, f, webRole, tenantA, tenantB) })
}

func (f *enrollmentFixture) lockRace(t *testing.T, kind, tenant string) {
	t.Helper()
	record, _, actor := f.fresh(t, tenant)
	if strings.HasPrefix(kind, "expiry-") {
		if _, err := f.owner.ExecContext(f.ctx, `UPDATE enroll_tokens SET expires_at=clock_timestamp()+interval '2 seconds' WHERE token_hash=$1`, record.TokenHash[:]); err != nil {
			t.Fatal(err)
		}
	}
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if kind == "expiry-token-lock" {
		_, err = blocker.ExecContext(f.ctx, `SELECT id FROM enroll_tokens WHERE token_hash=$1 FOR UPDATE`, record.TokenHash[:])
	} else {
		_, err = blocker.ExecContext(f.ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, actor)
	}
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := f.repository.Register(f.ctx, record, f.issue); done <- err }()
	waiting := false
	for range 100 {
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM pg_locks WHERE locktype='transactionid' AND NOT granted`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			waiting = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("enrollment did not reach the expected row lock")
	}
	if kind == "disable-user" {
		_, err = blocker.ExecContext(f.ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, actor)
	} else {
		var stillValid bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT expires_at>clock_timestamp() FROM enroll_tokens WHERE token_hash=$1`, record.TokenHash[:]).Scan(&stillValid); err != nil || !stillValid {
			t.Fatal("expiry test did not observe a lock wait while the token was valid")
		}
		_, err = f.owner.ExecContext(f.ctx, `SELECT pg_sleep(2.1)`)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, device.ErrDenied) {
			t.Fatal("eligibility change during a lock wait was accepted")
		}
	case <-f.ctx.Done():
		t.Fatal("blocked enrollment did not finish")
	}
	f.unused(t, record)
	f.noDevice(t, record.Candidates[0])
}
