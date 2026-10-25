package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testConsoleOIDCProviders(t *testing.T, ctx context.Context, owner, db *sql.DB) {
	var tenant, foreignTenant string
	for _, id := range []*string{&tenant, &foreignTenant} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('OIDC fixture') RETURNING id`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	user := func(scope, email, role string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,'fixture-only-hash') RETURNING id`, scope, email, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin := user(tenant, "oidc-admin@example.com", "admin")
	user(tenant, "oidc-backup@example.com", "admin")
	member := user(tenant, "oidc-member@example.com", "member")
	foreign := user(foreignTenant, "oidc-foreign@example.com", "admin")
	cipher, err := providersecret.New(bytes.Repeat([]byte{0x47}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var discoveries atomic.Int64
	validator := func(context.Context, web.OIDCProviderInput) error { discoveries.Add(1); return nil }
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: cipher, ValidateOIDC: validator}
	other := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: foreignTenant}, ProviderSecrets: cipher, ValidateOIDC: validator}
	ip := netip.MustParseAddr("::ffff:192.0.2.225")
	input := web.OIDCProviderInput{Slug: "primary", DisplayName: "Primary identity", IssuerURL: "https://idp.example", ClientID: "console-client", ClientSecret: "private-provider-fixture-value", Enabled: true}
	for _, actor := range []string{member, foreign} {
		if _, e := repo.CreateOIDCProvider(ctx, actor, input, ip); e == nil {
			t.Fatal("unauthorized creation")
		}
		if _, e := repo.OIDCProviders(ctx, actor, web.UserQuery{Limit: 10}); e == nil {
			t.Fatal("unauthorized listing")
		}
	}
	if discoveries.Load() != 0 {
		t.Fatal("unauthorized request reached discovery")
	}
	p, e := repo.CreateOIDCProvider(ctx, admin, input, ip)
	if e != nil || !p.HasClientSecret || len(p.Scopes) != 3 {
		t.Fatal("provider creation", e)
	}
	readSecret := func(id string) []byte {
		t.Helper()
		var value []byte
		if err := owner.QueryRowContext(ctx, `SELECT client_secret_enc FROM oidc_providers WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	sealed := readSecret(p.ID)
	if bytes.Contains(sealed, []byte(input.ClientSecret)) {
		t.Fatal("plaintext persisted")
	}
	binding := providersecret.Binding{TenantID: tenant, ProviderID: p.ID, Purpose: providersecret.OIDCClientSecret}
	plaintext, e := cipher.Open(binding, sealed)
	if e != nil || string(plaintext) != input.ClientSecret {
		t.Fatal("stored envelope did not authenticate", e)
	}
	clear(plaintext)
	if _, e = repo.CreateOIDCProvider(ctx, admin, input, ip); !errors.Is(e, web.ErrProviderSlugTaken) {
		t.Fatal("slug collision", e)
	}
	page, e := other.OIDCProviders(ctx, foreign, web.UserQuery{Limit: 10})
	if e != nil || len(page.Items) != 0 {
		t.Fatal("foreign provider visible", e)
	}
	name := "Renamed"
	if _, e = other.UpdateOIDCProvider(ctx, foreign, p.ID, web.OIDCProviderPatch{DisplayName: &name}, ip); !errors.Is(e, web.ErrOIDCNotFound) {
		t.Fatal("foreign provider writable", e)
	}
	if e = repo.DeleteOIDCProvider(ctx, member, p.ID, ip); !errors.Is(e, web.ErrForbidden) {
		t.Fatal("member deletion", e)
	}
	beforeDiscovery := discoveries.Load()
	repo.ValidateOIDC = func(context.Context, web.OIDCProviderInput) error { return errors.New("sensitive provider response") }
	no := false
	if _, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{DisplayName: &name, Enabled: &no}, ip); e != nil {
		t.Fatal("offline disable failed", e)
	}
	if discoveries.Load() != beforeDiscovery || !bytes.Equal(sealed, readSecret(p.ID)) {
		t.Fatal("offline edit fetched discovery or rotated omitted secret")
	}
	yes := true
	if _, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{Enabled: &yes}, ip); !errors.Is(e, web.ErrOIDCDiscovery) {
		t.Fatal("offline enable accepted", e)
	}
	repo.ValidateOIDC = validator
	if _, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{Enabled: &yes, ClientSecret: &input.ClientSecret}, ip); e != nil {
		t.Fatal(e)
	}
	rotated := readSecret(p.ID)
	if bytes.Equal(sealed, rotated) {
		t.Fatal("replacement reused nonce")
	}
	clientForEdit := "updated-with-existing-secret"
	repo.ValidateOIDC = func(_ context.Context, config web.OIDCProviderInput) error {
		if config.ClientSecret != input.ClientSecret || config.ClientID != clientForEdit {
			return errors.New("omitted credential was not restored for discovery")
		}
		return nil
	}
	if _, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{ClientID: &clientForEdit}, ip); e != nil || !bytes.Equal(rotated, readSecret(p.ID)) {
		t.Fatal("protocol edit lost the existing credential", e)
	}
	repo.ValidateOIDC = validator
	binding.ProviderID = "other-provider"
	if _, e = cipher.Open(binding, rotated); e == nil {
		t.Fatal("row substitution accepted")
	}
	binding.ProviderID = p.ID
	binding.TenantID = foreignTenant
	if _, e = cipher.Open(binding, rotated); e == nil {
		t.Fatal("tenant substitution accepted")
	}
	encoded, _ := json.Marshal(p)
	if strings.Contains(string(encoded), input.ClientSecret) || strings.Contains(string(encoded), "client_secret_enc") || strings.Contains(string(encoded), `"client_secret"`) {
		t.Fatal("secret in provider projection")
	}
	// A remote validation callback can acquire the actor row immediately: neither
	// the actor nor provider SQL locks are held during the remote operation.
	client := "changed-client"
	var demotionErr error
	repo.ValidateOIDC = func(callCtx context.Context, _ web.OIDCProviderInput) error {
		short, cancel := context.WithTimeout(callCtx, 500*time.Millisecond)
		defer cancel()
		_, demotionErr = owner.ExecContext(short, `UPDATE users SET role='member' WHERE id=$1`, admin)
		return demotionErr
	}
	_, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{ClientID: &client}, ip)
	if demotionErr != nil {
		t.Fatal("fixture administrator demotion did not commit", demotionErr)
	}
	if !errors.Is(e, web.ErrForbidden) {
		t.Fatal("authority change during discovery accepted or actor lock retained", e)
	}
	if _, e = owner.ExecContext(ctx, `UPDATE users SET role='admin' WHERE id=$1`, admin); e != nil {
		t.Fatal(e)
	}
	repo.ValidateOIDC = validator
	// Both edits read the same revision, then the non-network edit commits first.
	entered := make(chan struct{})
	release := make(chan struct{})
	repo.ValidateOIDC = func(callCtx context.Context, _ web.OIDCProviderInput) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-callCtx.Done():
			return callCtx.Err()
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{ClientID: &client}, ip)
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{DisplayName: &name}, ip); e != nil {
		close(release)
		t.Fatal(e)
	}
	close(release)
	if e = <-done; !errors.Is(e, web.ErrProviderChanged) {
		t.Fatal("concurrent provider edit overwritten", e)
	}
	repo.ValidateOIDC = validator
	// Issuer identity is immutable once bound. Disabling remains available.
	if _, e = owner.ExecContext(ctx, `INSERT INTO user_identities(tenant_id,user_id,provider_id,protocol,issuer,subject,email_at_link) VALUES($1,$2,$3,'oidc',$4,'subject-one','oidc-member@example.com')`, tenant, member, p.ID, input.IssuerURL); e != nil {
		t.Fatal(e)
	}
	issuer := "https://other-idp.example"
	if _, e = repo.UpdateOIDCProvider(ctx, admin, p.ID, web.OIDCProviderPatch{IssuerURL: &issuer}, ip); !errors.Is(e, web.ErrProviderInUse) {
		t.Fatal("bound issuer changed", e)
	}
	if e = repo.DeleteOIDCProvider(ctx, admin, p.ID, ip); !errors.Is(e, web.ErrProviderInUse) {
		t.Fatal("bound provider deleted", e)
	}
	input.Slug = "disposable"
	removable, e := repo.CreateOIDCProvider(ctx, admin, input, ip)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "restricted-oidc@example.com", Role: "member", ProviderID: &removable.ID}, ip)
	if e != nil {
		t.Fatal(e)
	}
	// Audit insertion failure rolls back the tombstone, secret deletion and grants.
	if _, e = owner.ExecContext(ctx, `CREATE FUNCTION reject_oidc_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'oidc_provider.%' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_oidc_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_oidc_audit()`); e != nil {
		t.Fatal(e)
	}
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_oidc_audit ON audit_log;DROP FUNCTION IF EXISTS reject_oidc_audit()`)
	if e = repo.DeleteOIDCProvider(ctx, admin, removable.ID, ip); e == nil {
		t.Fatal("deletion ignored audit failure")
	}
	input.Slug = "rolled-back"
	if _, e = repo.CreateOIDCProvider(ctx, admin, input, ip); e == nil {
		t.Fatal("creation ignored audit failure")
	}
	if _, e = repo.UpdateOIDCProvider(ctx, admin, removable.ID, web.OIDCProviderPatch{ClientID: &client}, ip); e == nil {
		t.Fatal("update ignored audit failure")
	}
	var intact bool
	if e = owner.QueryRowContext(ctx, `SELECT p.enabled AND p.deleted_at IS NULL AND o.client_secret_enc IS NOT NULL AND o.client_id=$3 AND i.cancelled_at IS NULL FROM identity_providers p JOIN oidc_providers o ON o.id=p.id JOIN invites i ON i.provider_id=p.id WHERE p.id=$1 AND i.id=$2`, removable.ID, grant.ID, input.ClientID).Scan(&intact); e != nil || !intact {
		t.Fatal("audit failure left partial provider state", e)
	}
	var count int
	if e = owner.QueryRowContext(ctx, `SELECT count(*) FROM identity_providers WHERE tenant_id=$1 AND slug='rolled-back'`, tenant).Scan(&count); e != nil || count != 0 {
		t.Fatal("failed create persisted", e)
	}
	if _, e = owner.ExecContext(ctx, `DROP TRIGGER reject_oidc_audit ON audit_log;DROP FUNCTION reject_oidc_audit()`); e != nil {
		t.Fatal(e)
	}
	if e = repo.DeleteOIDCProvider(ctx, admin, removable.ID, ip); e != nil {
		t.Fatal(e)
	}
	if e = owner.QueryRowContext(ctx, `SELECT NOT p.enabled AND p.deleted_at IS NOT NULL AND o.client_secret_enc IS NULL AND i.cancelled_at IS NOT NULL AND i.provider_id=p.id FROM identity_providers p JOIN oidc_providers o ON o.id=p.id JOIN invites i ON i.provider_id=p.id WHERE p.id=$1 AND i.id=$2`, removable.ID, grant.ID).Scan(&intact); e != nil || !intact {
		t.Fatal("provider history or invitation restriction lost", e)
	}
	digest, _ := auth.InvitationDigest(grant.Token)
	if _, e = repo.InspectInvitation(ctx, digest); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("deleted provider invitation still valid", e)
	}
	input.Slug = "disposable"
	if _, e = repo.CreateOIDCProvider(ctx, admin, input, ip); !errors.Is(e, web.ErrProviderSlugTaken) {
		t.Fatal("deleted callback slug reused", e)
	}
	input.Slug = "paginated"
	second, e := repo.CreateOIDCProvider(ctx, admin, input, ip)
	if e != nil {
		t.Fatal(e)
	}
	page, e = repo.OIDCProviders(ctx, admin, web.UserQuery{Limit: 1})
	if e != nil || len(page.Items) != 1 || page.NextCursor == nil {
		t.Fatal("first provider page", e)
	}
	after, e := base64.RawURLEncoding.Strict().DecodeString(*page.NextCursor)
	if e != nil {
		t.Fatal(e)
	}
	last, e := repo.OIDCProviders(ctx, admin, web.UserQuery{Limit: 1, AfterID: string(after)})
	if e != nil || len(last.Items) != 1 || last.NextCursor != nil || last.Items[0].ID == page.Items[0].ID {
		t.Fatal("next provider page", e)
	}
	seen := map[string]bool{page.Items[0].ID: true, last.Items[0].ID: true}
	if !seen[p.ID] || !seen[second.ID] || seen[removable.ID] {
		t.Fatal("pagination lost a provider or returned a tombstone")
	}
	empty := ""
	public, e := repo.UpdateOIDCProvider(ctx, admin, second.ID, web.OIDCProviderPatch{ClientSecret: &empty}, ip)
	if e != nil || public.HasClientSecret || readSecret(second.ID) != nil {
		t.Fatal("explicit public-client secret removal", e)
	}
	var audit string
	if e = owner.QueryRowContext(ctx, `SELECT jsonb_agg(payload)::text FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(audit, input.ClientSecret) || strings.Contains(audit, grant.Token) || !strings.Contains(audit, "192.0.2.225") {
		t.Fatal("audit leaked credentials or lost normalized source")
	}
	t.Log("OIDC provider SQL verified tenant/admin isolation, encrypted writes, omitted-secret preservation, nonce rotation, offline disable, live authority recheck, concurrent edit refusal, bound issuer/deletion guards, audit rollback and retained restricted-invitation history; discovery transport is tested separately")
}
