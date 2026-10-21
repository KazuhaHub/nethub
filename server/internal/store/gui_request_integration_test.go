package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/jackc/pgx/v5/pgconn"
)

func testGUIRequests(t *testing.T, f *enrollmentFixture, web *sql.DB, tenantA, tenantB string) {
	const domain = "devices.example.com"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	registration, _, _ := f.fresh(t, tenantA)
	registration.GUIPublicKey = base64.RawURLEncoding.EncodeToString(spki)
	assigned, err := f.repository.Register(f.ctx, registration, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	credential := device.Credential{TenantID: tenantA, Hash: registration.SecretHash}
	repository := &GUIRequestStore{Enrollment: f.repository, DeviceDomain: domain}
	if err := repository.Health(f.ctx); err != nil {
		t.Fatal("certificate admission not ready", err)
	}
	t.Run("readiness_requires_binding_guard", func(t *testing.T) {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE gui_certificate_requests DISABLE TRIGGER gui_certificate_request_binding`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE gui_certificate_requests ENABLE TRIGGER gui_certificate_request_binding`); err != nil {
				t.Fatal(err)
			}
		}()
		if repository.Health(f.ctx) == nil {
			t.Fatal("admission ready without binding guard")
		}
	})
	makeCSR := func(host string, signer *ecdsa.PrivateKey) ([]byte, []byte) {
		t.Helper()
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}, SignatureAlgorithm: x509.ECDSAWithSHA256}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), der
	}
	host := assigned.Subdomain + "." + domain
	encoded, der := makeCSR(host, key)
	changed, _ := makeCSR(host, key)
	if bytes.Equal(encoded, changed) {
		t.Fatal("fixture signatures unexpectedly identical")
	}
	if _, found, err := repository.Read(f.ctx, credential, assigned.ID); err != nil || found {
		t.Fatal("new binding already has a request", err)
	}
	for _, input := range [][]byte{nil, []byte("invalid"), bytes.Repeat([]byte{'x'}, 8193)} {
		if _, err := repository.Admit(f.ctx, credential, assigned.ID, input); !errors.Is(err, guicert.ErrRequest) {
			t.Fatal("malformed CSR admitted", err)
		}
	}
	wrongHost, _ := makeCSR("other.example.com", key)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := makeCSR(host, otherKey)
	for _, input := range [][]byte{wrongHost, wrongKey} {
		if _, err := repository.Admit(f.ctx, credential, assigned.ID, input); !errors.Is(err, guicert.ErrRequest) {
			t.Fatal("unbound CSR admitted", err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan GUIRequest, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			r, err := repository.Admit(f.ctx, credential, assigned.ID, encoded)
			if err != nil {
				failures <- err
			} else {
				results <- r
			}
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal("concurrent identical admission failed", err)
	}
	var saved GUIRequest
	for got := range results {
		if saved.ID != "" && got.ID != saved.ID {
			t.Fatal("retry created a second request")
		}
		saved = got
	}
	digest := sha256.Sum256(der)
	if saved.ID == "" || !bytes.Equal(saved.DER, der) || saved.Fingerprint != hex.EncodeToString(digest[:]) || saved.PublicKey != registration.GUIPublicKey || saved.AssignedHost != host {
		t.Fatal("request identity was not persisted")
	}
	if value, err := json.Marshal(saved); err != nil || string(value) != "{}" {
		t.Fatal("raw request leaked into ordinary JSON")
	}
	if _, err := repository.Admit(f.ctx, credential, assigned.ID, changed); !errors.Is(err, ErrGUIRequestConflict) {
		t.Fatal("changed signed bytes replaced request", err)
	}
	recovered, found, err := repository.Read(f.ctx, credential, assigned.ID)
	if err != nil || !found || recovered.ID != saved.ID || !bytes.Equal(recovered.DER, der) {
		t.Fatal("original signed request recovery failed", err)
	}
	var count int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.certificate_requested'`, assigned.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("retries duplicated admission audit", err)
	}
	expectSQL := func(role *sql.DB, tenant, code, query string, args ...any) {
		t.Helper()
		tx, err := role.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(f.ctx, query, args...)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("expected SQLSTATE %s, got %v", code, err)
		}
	}
	for _, role := range []*sql.DB{f.owner, f.repository.DB} {
		code := "P0001"
		if role == f.repository.DB {
			code = "42501"
		}
		expectSQL(role, tenantA, code, `UPDATE gui_certificate_requests SET csr_der=$1 WHERE id=$2`, der, saved.ID)
		expectSQL(role, tenantA, code, `DELETE FROM gui_certificate_requests WHERE id=$1`, saved.ID)
	}
	expectSQL(web, tenantA, "42501", `SELECT csr_der FROM gui_certificate_requests WHERE id=$1`, saved.ID)
	expectSQL(web, tenantA, "42501", `INSERT INTO gui_certificate_requests(tenant_id,device_id,assigned_host,gui_public_key,csr_der) VALUES($1,$2,$3,$4,$5)`, tenantA, assigned.ID, host, registration.GUIPublicKey, der)
	tx, err := f.repository.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantB); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_requests`).Scan(&count); err != nil || count != 0 {
		t.Fatal("cross-tenant CSR visible", err)
	}
	tx.Rollback()
	if _, _, err := repository.Read(f.ctx, device.Credential{TenantID: tenantB, Hash: credential.Hash}, assigned.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("cross-tenant credential accepted", err)
	}
	for _, badDomain := range []string{"EXAMPLE.com", "example.com/route", "127.0.0.1", "*.example.com", "localhost"} {
		bad := &GUIRequestStore{Enrollment: f.repository, DeviceDomain: badDomain}
		if _, _, err := bad.Read(f.ctx, credential, assigned.ID); !errors.Is(err, device.ErrUnavailable) {
			t.Fatal("invalid deployment domain admitted", err)
		}
	}
	differentDomain := &GUIRequestStore{Enrollment: f.repository, DeviceDomain: "changed.example.com"}
	if _, _, err := differentDomain.Read(f.ctx, credential, assigned.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("changed assignment returned old CSR", err)
	}
	// A rotated credential can recover the same CSR; stale verified credentials fail.
	newHash := credential.Hash + "-rotated-fixture"
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET device_secret_hash=$1 WHERE id=$2`, newHash, assigned.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.Read(f.ctx, credential, assigned.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("stale credential recovered CSR", err)
	}
	credential.Hash = newHash
	if got, found, err := repository.Read(f.ctx, credential, assigned.ID); err != nil || !found || got.ID != saved.ID {
		t.Fatal("credential rotation lost original CSR", err)
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, assigned.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.Read(f.ctx, credential, assigned.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("revoked device recovered CSR", err)
	}
	if _, err := repository.Admit(f.ctx, credential, assigned.ID, encoded); !errors.Is(err, device.ErrDenied) {
		t.Fatal("revoked device resubmitted CSR", err)
	}
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_requests WHERE id=$1`, saved.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("revocation deleted retained request", err)
	}
	legacy, _, _ := f.fresh(t, tenantA)
	legacyDevice, err := f.repository.Register(f.ctx, legacy, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.Read(f.ctx, device.Credential{TenantID: tenantA, Hash: legacy.SecretHash}, legacyDevice.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("legacy unbound device accepted", err)
	}
	expectSQL(f.repository.DB, tenantA, "23514", `INSERT INTO gui_certificate_requests(tenant_id,device_id,assigned_host,gui_public_key,csr_der) VALUES($1,$2,$3,$4,$5)`, tenantA, legacyDevice.ID, legacyDevice.Subdomain+"."+domain, registration.GUIPublicKey, der)
	t.Run("revocation_wins_waiting_admission", func(t *testing.T) {
		r, _, _ := f.fresh(t, tenantA)
		r.GUIPublicKey = registration.GUIPublicKey
		a, err := f.repository.Register(f.ctx, r, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		csr, _ := makeCSR(a.Subdomain+"."+domain, key)
		tx, err := f.owner.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		var blocker int
		if err := tx.QueryRowContext(f.ctx, `SELECT pg_backend_pid() FROM devices WHERE id=$1 FOR UPDATE`, a.ID).Scan(&blocker); err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() {
			_, err := repository.Admit(f.ctx, device.Credential{TenantID: tenantA, Hash: r.SecretHash}, a.ID, csr)
			finished <- err
		}()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var waiting bool
			if err := f.repository.DB.QueryRowContext(f.ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case err := <-finished:
				t.Fatal("admission bypassed held assignment lock", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("admission did not reach assignment lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, err := tx.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, a.ID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; !errors.Is(err, device.ErrDenied) {
			t.Fatal("revocation raced past CSR admission", err)
		}
		var count int
		if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_requests WHERE device_id=$1`, a.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("revoked waiting admission persisted a CSR", err)
		}
	})
	t.Log("Immutable CSR admission, concurrent idempotency, exact recovery, one audit, credential/assignment/revocation checks and actual role/RLS boundaries passed")
}
