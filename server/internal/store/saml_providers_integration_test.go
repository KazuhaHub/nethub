package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func samlProviderTestMetadata(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:provider:test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/login"/></IDPSSODescriptor></EntityDescriptor>`, base64.StdEncoding.EncodeToString(der))
}

func testConsoleSAMLProviders(t *testing.T, ctx context.Context, owner, db *sql.DB) {
	var tenant, foreign string
	for _, id := range []*string{&tenant, &foreign} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('SAML providers fixture') RETURNING id`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	user := func(scope, role, email string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,'fixture-only-hash') RETURNING id`, scope, email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin := user(tenant, "admin", "saml-admin@example.com")
	user(tenant, "admin", "saml-backup@example.com")
	member := user(tenant, "member", "saml-member@example.com")
	foreignAdmin := user(foreign, "admin", "foreign@example.com")
	cipher, err := providersecret.New(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var validations atomic.Int64
	validator := func(context.Context, web.SAMLProviderInput) error { validations.Add(1); return nil }
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: cipher, ValidateSAML: validator}
	other := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: foreign}, ProviderSecrets: cipher, ValidateSAML: validator}
	ip := netip.MustParseAddr("192.0.2.229")
	input := web.SAMLProviderInput{Slug: "primary-saml", DisplayName: "Company SAML", EntityID: "urn:provider:test", MetadataXML: samlProviderTestMetadata(t), EmailAttribute: "mail", Enabled: true}
	for _, actor := range []string{member, foreignAdmin} {
		if _, err := repo.CreateSAMLProvider(ctx, actor, input, ip); err == nil {
			t.Fatal("unauthorized create")
		}
		if _, err := repo.SAMLProviders(ctx, actor, web.UserQuery{Limit: 10}); err == nil {
			t.Fatal("unauthorized list")
		}
	}
	if validations.Load() != 0 {
		t.Fatal("unauthorized metadata validation")
	}
	p, err := repo.CreateSAMLProvider(ctx, admin, input, ip)
	if err != nil || !p.HasSigningKey {
		t.Fatal("provider creation", err)
	}
	readKey := func(id string) []byte {
		t.Helper()
		var key []byte
		if err := owner.QueryRowContext(ctx, `SELECT sp_key_enc FROM saml_providers WHERE id=$1`, id).Scan(&key); err != nil {
			t.Fatal(err)
		}
		return key
	}
	sealed := readKey(p.ID)
	if bytes.Contains(sealed, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext signing key stored")
	}
	bundle, err := cipher.Open(providersecret.Binding{TenantID: tenant, ProviderID: p.ID, Purpose: providersecret.SAMLSigningKey}, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sso.ParseSAMLSigningIdentity(bundle); err != nil {
		t.Fatal("stored signing identity", err)
	}
	clear(bundle)
	metadataURI := "https://console.example.com/api/v1/console/saml/primary-saml/metadata"
	acs := "https://console.example.com/api/v1/console/saml/primary-saml/callback"
	public, err := repo.SAMLMetadata(ctx, p.Slug, metadataURI, acs)
	if err != nil || bytes.Contains(public, []byte("PRIVATE KEY")) || !bytes.Contains(public, []byte(acs)) {
		t.Fatal("public SP metadata", err)
	}
	if _, err := other.SAMLMetadata(ctx, p.Slug, metadataURI, acs); !errors.Is(err, web.ErrSAMLNotFound) {
		t.Fatal("cross-tenant metadata", err)
	}
	no := false
	name := "Renamed"
	repo.ValidateSAML = func(context.Context, web.SAMLProviderInput) error { return errors.New("private validation failure") }
	if _, err := repo.UpdateSAMLProvider(ctx, admin, p.ID, web.SAMLProviderPatch{Enabled: &no, DisplayName: &name}, ip); err != nil {
		t.Fatal("offline disable", err)
	}
	if !bytes.Equal(sealed, readKey(p.ID)) {
		t.Fatal("ordinary edit rotated signing identity")
	}
	yes := true
	if _, err := repo.UpdateSAMLProvider(ctx, admin, p.ID, web.SAMLProviderPatch{Enabled: &yes}, ip); !errors.Is(err, web.ErrSAMLMetadata) {
		t.Fatal("validation failure enabled provider", err)
	}
	repo.ValidateSAML = validator
	if _, err := repo.UpdateSAMLProvider(ctx, admin, p.ID, web.SAMLProviderPatch{Enabled: &yes}, ip); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	repo.ValidateSAML = func(context.Context, web.SAMLProviderInput) error { close(entered); <-release; return nil }
	done := make(chan error, 1)
	document := input.MetadataXML
	go func() {
		_, err := repo.UpdateSAMLProvider(ctx, admin, p.ID, web.SAMLProviderPatch{MetadataXML: &document}, ip)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("validation not entered")
	}
	if _, err := owner.ExecContext(ctx, `UPDATE identity_providers SET revision=revision+1 WHERE id=$1`, p.ID); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, web.ErrProviderChanged) {
		t.Fatal("stale update won", err)
	}
	repo.ValidateSAML = validator
	if _, err := owner.ExecContext(ctx, `INSERT INTO user_identities(tenant_id,user_id,provider_id,protocol,issuer,subject,email_at_link) VALUES($1,$2,$3,'saml',$4,'stable-nameid','saml-member@example.com')`, tenant, member, p.ID, input.EntityID); err != nil {
		t.Fatal(err)
	}
	issuer := "urn:provider:changed"
	changed := strings.ReplaceAll(document, input.EntityID, issuer)
	if _, err := repo.UpdateSAMLProvider(ctx, admin, p.ID, web.SAMLProviderPatch{EntityID: &issuer, MetadataXML: &changed}, ip); !errors.Is(err, web.ErrProviderInUse) {
		t.Fatal("bound issuer changed", err)
	}
	if err := repo.DeleteSAMLProvider(ctx, admin, p.ID, ip); !errors.Is(err, web.ErrProviderInUse) {
		t.Fatal("bound provider deleted", err)
	}
	input.Slug = "removable-saml"
	disposable, err := repo.CreateSAMLProvider(ctx, admin, input, ip)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "restricted-saml@example.com", Role: "member", ProviderID: &disposable.ID}, ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `CREATE FUNCTION reject_saml_provider_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'saml_provider.%' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_saml_provider_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_saml_provider_audit()`); err != nil {
		t.Fatal(err)
	}
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_saml_provider_audit ON audit_log;DROP FUNCTION IF EXISTS reject_saml_provider_audit()`)
	if err := repo.DeleteSAMLProvider(ctx, admin, disposable.ID, ip); err == nil {
		t.Fatal("audit failure ignored")
	}
	var intact bool
	if err := owner.QueryRowContext(ctx, `SELECT p.deleted_at IS NULL AND s.sp_key_enc IS NOT NULL AND i.cancelled_at IS NULL FROM identity_providers p JOIN saml_providers s ON s.id=p.id JOIN invites i ON i.provider_id=p.id WHERE p.id=$1 AND i.id=$2`, disposable.ID, grant.ID).Scan(&intact); err != nil || !intact {
		t.Fatal("partial failed deletion", err)
	}
	if _, err := owner.ExecContext(ctx, `DROP TRIGGER reject_saml_provider_audit ON audit_log;DROP FUNCTION reject_saml_provider_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteSAMLProvider(ctx, admin, disposable.ID, ip); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx, `SELECT NOT p.enabled AND p.deleted_at IS NOT NULL AND s.sp_key_enc IS NULL AND i.cancelled_at IS NOT NULL AND i.provider_id=p.id FROM identity_providers p JOIN saml_providers s ON s.id=p.id JOIN invites i ON i.provider_id=p.id WHERE p.id=$1 AND i.id=$2`, disposable.ID, grant.ID).Scan(&intact); err != nil || !intact {
		t.Fatal("history or key removal failed", err)
	}
	if _, err := repo.CreateSAMLProvider(ctx, admin, input, ip); !errors.Is(err, web.ErrProviderSlugTaken) {
		t.Fatal("tombstoned callback reused", err)
	}
	t.Log("SAML provider SQL verified administrator and tenant boundaries, encrypted independent SP keys, public metadata, offline disable, revision fences, stable bound issuer, audit rollback and retained invitation restrictions")
}
