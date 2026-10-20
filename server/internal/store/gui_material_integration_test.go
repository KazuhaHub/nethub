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
	if _, err := requests.Admit(f.ctx, credential, a.ID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})); err != nil {
		t.Fatal(err)
	}
	id, err := (&GUIJobQueue{Requests: requests}).Enqueue(f.ctx, credential, a.ID)
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
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
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
}
