package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/jackc/pgx/v5/pgconn"
)

func testGUIIssuedMaterial(t *testing.T, f *enrollmentFixture, tenant string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	r, _, _ := f.fresh(t, tenant)
	r.GUIPublicKey = base64.RawURLEncoding.EncodeToString(public)
	a, err := f.repository.Register(f.ctx, r, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	requests := &GUIRequestStore{Enrollment: f.repository, DeviceDomain: "devices.example.com"}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{a.Subdomain + ".devices.example.com"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		t.Fatal(err)
	}
	credential := device.Credential{TenantID: tenant, Hash: r.SecretHash}
	request, err := requests.Admit(f.ctx, credential, a.ID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err != nil {
		t.Fatal(err)
	}
	queue := &GUIJobQueue{Requests: requests}
	if err := queue.Health(f.ctx); err != nil {
		t.Fatal("delivery authorization readiness", err)
	}
	func() {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER FUNCTION read_issued_gui_certificate(uuid,uuid,text,text) SECURITY INVOKER`); err != nil {
			t.Fatal("delivery function guard fault", err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER FUNCTION read_issued_gui_certificate(uuid,uuid,text,text) SECURITY DEFINER`); err != nil {
				t.Error("delivery function guard restore", err)
			}
		}()
		if queue.Health(f.ctx) == nil {
			t.Fatal("delivery ready with altered function identity")
		}
	}()
	if _, pending, err := queue.Issued(f.ctx, credential, a.ID, request.ID, request.Fingerprint); err != nil || pending != nil {
		t.Fatal("admitted request should have pending delivery", err)
	}
	id, err := queue.Enqueue(f.ctx, credential, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	account, err := guiacme.NewAccountStore(filepath.Join(t.TempDir(), "account"), guiacme.Config{DirectoryURL: "https://acme.example.test/directory", ContactEmail: "issuer@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &guiissuer.SQLStore{Run: issuerSQLInput, Domain: "devices.example.com", AllowsURL: account.AllowsURL}
	if err := adapter.Ready(f.ctx); err != nil {
		t.Fatal("host issuer schema/identity readiness failed")
	}
	if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices DISABLE TRIGGER devices_cancel_gui_jobs`); err != nil {
		t.Fatal(err)
	}
	notReady := adapter.Ready(f.ctx)
	if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices ENABLE TRIGGER devices_cancel_gui_jobs`); err != nil {
		t.Fatal(err)
	}
	if notReady == nil {
		t.Fatal("host issuer accepted a disabled cancellation guard")
	}
	claimed, err := adapter.Claim(f.ctx)
	if err != nil {
		t.Fatal("issued fixture claim failed")
	}
	if claimed == nil || claimed.Lease.ID != id {
		t.Fatal("issued fixture work mismatch", err)
	}
	work, err := adapter.Renew(f.ctx, *claimed)
	if err != nil {
		t.Fatal("issued fixture renewal failed", err)
	}
	work = *testGUIProgress(t, f, &work)
	progress, err := adapter.Read(f.ctx, work)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "Private fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(102), DNSNames: []string{work.Host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	material, err := guiissuer.PrepareMaterial(work, progress, chain, roots, account.AllowsURL, now)
	if err != nil {
		t.Fatal("independent issued chain validation failed", err)
	}
	finish := func(w guiissuer.Snapshot, m guiissuer.Material) string {
		t.Helper()
		result, err := adapter.Finish(f.ctx, w, m)
		if errors.Is(err, guiissuer.ErrDatabase) {
			return "null"
		}
		if err != nil {
			t.Fatal("issued material commit failed")
		}
		return result
	}
	stale := work
	stale.Lease.Version--
	if finish(stale, material) != "null" {
		t.Fatal("stale worker committed issued material")
	}
	generation := finish(work, material)
	if generation == "null" || len(generation) != 36 {
		t.Fatal("issued generation missing")
	}
	if finish(work, material) != generation {
		t.Fatal("lost completion reply could not recover the same generation")
	}
	read, delivered, err := queue.Issued(f.ctx, credential, a.ID, request.ID, request.Fingerprint)
	if err != nil || delivered == nil || read.ID != request.ID || delivered.ID != generation || delivered.Generation != 1 || !bytes.Equal(delivered.PEM, material.PEM) {
		t.Fatal("authorized original request did not receive exact issued public material", err)
	}
	func() {
		// Change only this disposable generation's clock metadata, with the
		// immutable guard restored before any reader runs. No host clock changes.
		var issuedAt time.Time
		if err := f.owner.QueryRowContext(f.ctx, `SELECT issued_at FROM gui_certificate_generations WHERE id=$1`, generation).Scan(&issuedAt); err != nil {
			t.Fatal(err)
		}
		setTimes := func(until, renew, issued time.Time) error {
			tx, err := f.owner.BeginTx(f.ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(f.ctx, `ALTER TABLE gui_certificate_generations DISABLE TRIGGER gui_certificate_generation_immutable`); err != nil {
				return err
			}
			result, err := tx.ExecContext(f.ctx, `UPDATE gui_certificate_generations SET valid_until=$2,renew_after=$3,issued_at=$4 WHERE id=$1`, generation, until, renew, issued)
			if err != nil {
				return err
			}
			if count, err := result.RowsAffected(); err != nil || count != 1 {
				return errors.New("owned expiry fixture changed no exact generation")
			}
			if _, err := tx.ExecContext(f.ctx, `ALTER TABLE gui_certificate_generations ENABLE TRIGGER gui_certificate_generation_immutable`); err != nil {
				return err
			}
			return tx.Commit()
		}
		clock := time.Now().UTC()
		if err := setTimes(clock.Add(-time.Second), clock.Add(-2*time.Second), clock.Add(-3*time.Second)); err != nil {
			t.Fatal("disposable generation expiry fault", err)
		}
		defer func() {
			if err := setTimes(delivered.ValidUntil, delivered.RenewAfter, issuedAt); err != nil {
				t.Error("disposable expiry restoration", err)
			}
		}()
		if _, expired, err := queue.Issued(f.ctx, credential, a.ID, request.ID, request.Fingerprint); err != nil || expired != nil {
			t.Fatal("expired public material was delivered", err)
		}
		report := guicert.ApplicationReport{DeviceID: a.ID, RequestID: request.ID, RequestFingerprint: request.Fingerprint,
			GenerationID: delivered.ID, Generation: delivered.Generation, Fingerprint: delivered.Fingerprint}
		if _, err := queue.Acknowledge(f.ctx, credential, report); !errors.Is(err, device.ErrDenied) {
			t.Fatal("expired generation was acknowledged", err)
		}
	}()
	application := testGUIApplicationReports(t, f, queue, credential, request, delivered)
	for _, wrong := range []struct{ id, fingerprint string }{
		{"00000000-0000-0000-0000-000000000000", request.Fingerprint},
		{request.ID, strings.Repeat("0", 64)},
	} {
		if _, _, err := queue.Issued(f.ctx, credential, a.ID, wrong.id, wrong.fingerprint); !errors.Is(err, device.ErrDenied) {
			t.Fatal("delivery accepted a different request binding", err)
		}
	}
	foreign := credential
	foreign.TenantID = "00000000-0000-0000-0000-000000000000"
	if _, _, err := queue.Issued(f.ctx, foreign, a.ID, request.ID, request.Fingerprint); !errors.Is(err, device.ErrDenied) {
		t.Fatal("cross-tenant delivery accepted", err)
	}
	wrongSecret := credential
	wrongSecret.Hash += "changed"
	if _, _, err := queue.Issued(f.ctx, wrongSecret, a.ID, request.ID, request.Fingerprint); !errors.Is(err, device.ErrDenied) {
		t.Fatal("changed credential received public material", err)
	}
	changed := material
	changed.PEM = append(bytes.Clone(material.PEM), []byte("changed")...)
	if finish(work, changed) != "null" {
		t.Fatal("completion retry replaced issued material")
	}
	var state string
	var count int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT state FROM gui_certificate_jobs WHERE id=$1`, id).Scan(&state); err != nil || state != "issued" {
		t.Fatal("issued job state not committed", err)
	}
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.certificate_issued'`, a.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("completion retry duplicated issuance audit", err)
	}
	for _, statement := range []string{`UPDATE gui_certificate_generations SET chain_pem='changed' WHERE id=$1`, `DELETE FROM gui_certificate_generations WHERE id=$1`} {
		_, err := f.owner.ExecContext(f.ctx, statement, generation)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "P0001" {
			t.Fatal("issued generation mutated through ordinary SQL", err)
		}
	}
	for _, role := range []string{"nethub_web", "nethub_authz", "nethub_issuer"} {
		var allowed bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT has_table_privilege($1,'public.gui_certificate_generations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, role).Scan(&allowed); err != nil || allowed {
			t.Fatal("issued material raw table exposed", err)
		}
	}
	testRevocationFencesGUIApplication(t, f, queue, credential, application)
	if _, _, err := queue.Issued(f.ctx, credential, a.ID, request.ID, request.Fingerprint); !errors.Is(err, device.ErrDenied) {
		t.Fatal("revoked device received retained issued material", err)
	}
	if finish(work, material) != "null" {
		t.Fatal("revoked assignment recovered completion material")
	}
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM gui_certificate_generations WHERE id=$1`, generation).Scan(&count); err != nil || count != 1 {
		t.Fatal("revocation deleted issued evidence", err)
	}
	if strings.Contains(string(material.PEM), "PRIVATE KEY") {
		t.Fatal("device key entered installation material")
	}
	t.Log("Independently validated original-key issued chain, lease CAS, exact lost-reply completion, immutable generation/audit, private grants and revoked retention passed; native application not claimed")
	t.Log("Private SQL adapter claim/renew/read/save/finish, lost-reply and stale-version recovery passed against the real issuer identity")
	t.Log("Authenticated public generation delivery passed pending/exact-original material, expiry filtering, changed-function readiness, wrong request/fingerprint/tenant/credential refusal and revoked retention without raw table grants")
}
