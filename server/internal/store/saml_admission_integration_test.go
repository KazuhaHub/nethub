package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

func testSAMLBrowserAdmission(t *testing.T, ctx context.Context, owner, db, authz, backup *sql.DB) {
	var tenant, foreign string
	for _, id := range []*string{&tenant, &foreign} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('SAML admission fixture') RETURNING id`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	var admin string
	if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,'saml-flow-admin@example.com','admin','fixture-only-hash') RETURNING id`, tenant).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	cipher, err := providersecret.New(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: cipher, ValidateSAML: func(context.Context, web.SAMLProviderInput) error { return nil }}
	other := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: foreign}, ProviderSecrets: cipher}
	ip := netip.MustParseAddr("192.0.2.231")
	input := web.SAMLProviderInput{Slug: "saml-flow", DisplayName: "SAML flow", EntityID: "urn:provider:test", EmailAttribute: "mail", MetadataXML: samlProviderTestMetadata(t), Enabled: true}
	p, err := repo.CreateSAMLProvider(ctx, admin, input, ip)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := repo.SAMLLoginProvider(ctx, p.Slug)
	if err != nil {
		t.Fatal(err)
	}
	opaque := func() string {
		t.Helper()
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	type fixture struct {
		id    string
		input sso.SAMLFlowInput
	}
	flow := func(invitation []byte) fixture {
		t.Helper()
		browser, _ := sso.Digest(opaque())
		value := sso.SAMLFlowInput{Provider: loaded, State: opaque(), RequestID: "request-" + opaque(), BrowserDigest: browser, InvitationDigest: invitation}
		if _, err := repo.SaveSAMLFlow(ctx, value); err != nil {
			t.Fatal(err)
		}
		digest, _ := sso.Digest(value.State)
		var id string
		if err := owner.QueryRowContext(ctx, `SELECT id FROM saml_flows WHERE state_hash=$1`, digest).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return fixture{id: id, input: value}
	}
	consume := func(f fixture) sso.ConsumedSAMLFlow {
		t.Helper()
		value, err := repo.ConsumeSAMLFlow(ctx, p.Slug, f.input.State, f.input.BrowserDigest)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	identity := func(f sso.ConsumedSAMLFlow, subject, email string, signed bool) auth.ExternalIdentity {
		return auth.ExternalIdentity{Protocol: "saml", FlowID: f.ID, ProviderID: p.ID, ProviderRevision: f.Provider.Revision, Issuer: p.EntityID, Subject: subject, Email: email, SignedEmail: signed}
	}
	var sequence atomic.Uint64
	record := func() auth.SessionRecord {
		n := sequence.Add(1)
		token := sha256.Sum256(fmt.Appendf(nil, "saml-token-%d", n))
		csrf := sha256.Sum256(fmt.Appendf(nil, "saml-csrf-%d", n))
		now := time.Now().UTC()
		return auth.SessionRecord{TokenHash: token[:], CSRFHash: csrf[:], CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: ip, UserAgent: "SAML SQL fixture"}
	}
	f := flow(nil)
	var forced bool
	if err := owner.QueryRowContext(ctx, `SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='saml_flows'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatal("SAML flows lack forced tenant RLS", err)
	}
	if _, err := authz.ExecContext(ctx, `SELECT id FROM saml_flows`); err == nil {
		t.Fatal("authz read browser flows")
	} else {
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("unexpected authz failure", err)
		}
	}
	if _, err := backup.ExecContext(ctx, `DELETE FROM saml_flows WHERE false`); err == nil {
		t.Fatal("backup can mutate browser flows")
	} else {
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("unexpected backup failure", err)
		}
	}
	var encrypted, storedState []byte
	if err := owner.QueryRowContext(ctx, `SELECT protocol_state_enc,state_hash FROM saml_flows WHERE id=$1`, f.id).Scan(&encrypted, &storedState); err != nil {
		t.Fatal(err)
	}
	want, _ := sso.Digest(f.input.State)
	if !bytes.Equal(want, storedState) || bytes.Contains(encrypted, []byte(f.input.RequestID)) || bytes.Contains(encrypted, []byte(f.input.State)) {
		t.Fatal("raw protocol values stored")
	}
	if _, err := cipher.Open(providersecret.Binding{TenantID: tenant, ProviderID: f.id, Purpose: providersecret.OIDCFlowState}, encrypted); err == nil {
		t.Fatal("SAML flow opened with OIDC purpose")
	}
	for _, attempt := range []struct {
		repo    *ConsoleStore
		slug    string
		browser []byte
	}{{repo, "other", f.input.BrowserDigest}, {repo, p.Slug, bytes.Repeat([]byte{1}, 32)}, {other, p.Slug, f.input.BrowserDigest}} {
		if _, err := attempt.repo.ConsumeSAMLFlow(ctx, attempt.slug, f.input.State, attempt.browser); !errors.Is(err, sso.ErrFlow) {
			t.Fatal("foreign browser/provider/tenant consumed flow", err)
		}
	}
	fresh := &ConsoleStore{AuthStore: repo.AuthStore, ProviderSecrets: cipher}
	restored, err := fresh.ConsumeSAMLFlow(ctx, p.Slug, f.input.State, f.input.BrowserDigest)
	if err != nil || restored.RequestID != f.input.RequestID {
		t.Fatal("fresh repository lost durable request", err)
	}
	if _, err := repo.CreateExternalSession(ctx, identity(restored, "uninvited", "saml-flow-admin@example.com", true), record()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("mailbox matching admitted existing user", err)
	}
	f = flow(nil)
	var winners atomic.Int64
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			if _, err := repo.ConsumeSAMLFlow(ctx, p.Slug, f.input.State, f.input.BrowserDigest); err == nil {
				winners.Add(1)
			}
		})
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatal("concurrent flow consumption", winners.Load())
	}
	var cleared bool
	if err := owner.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL AND protocol_state_enc IS NULL FROM saml_flows WHERE id=$1`, f.id).Scan(&cleared); err != nil || !cleared {
		t.Fatal("consumed request retained secret state", err)
	}
	grant, err := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "saml-invite@example.com", Role: "member", ProviderID: &p.ID}, ip)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := auth.InvitationDigest(grant.Token)
	f = flow(digest)
	consumed := consume(f)
	wrongProtocol := identity(consumed, "saml-subject", "saml-invite@example.com", true)
	wrongProtocol.Protocol = "oidc"
	wrongProtocol.EmailVerified = true
	if _, err := repo.CreateExternalSession(ctx, wrongProtocol, record()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("SAML receipt admitted through OIDC", err)
	}
	unsigned := identity(consumed, "saml-subject", "saml-invite@example.com", false)
	unsigned.EmailVerified = true
	if _, err := repo.CreateExternalSession(ctx, unsigned, record()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("OIDC email flag substituted for signed SAML mail", err)
	}
	winners.Store(0)
	for range 8 {
		wait.Go(func() {
			if _, err := repo.CreateExternalSession(ctx, identity(consumed, "saml-subject", "saml-invite@example.com", true), record()); err == nil {
				winners.Add(1)
			}
		})
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatal("concurrent SAML invitation admission", winners.Load())
	}
	var userID string
	if err := owner.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE tenant_id=$1 AND protocol='saml' AND subject='saml-subject'`, tenant).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	f = flow(nil)
	if _, err := repo.CreateExternalSession(ctx, identity(consume(f), "saml-subject", "", false), record()); err != nil {
		t.Fatal("stable bound identity required a new email claim", err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	f = flow(nil)
	if _, err := repo.CreateExternalSession(ctx, identity(consume(f), "saml-subject", "saml-invite@example.com", true), record()); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("disabled SAML account admitted", err)
	}
	stale := flow(nil)
	if _, err := owner.ExecContext(ctx, `UPDATE identity_providers SET revision=revision+1 WHERE id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeSAMLFlow(ctx, p.Slug, stale.input.State, stale.input.BrowserDigest); !errors.Is(err, sso.ErrFlow) {
		t.Fatal("stale provider request consumed", err)
	}
	t.Run("bounded_capacity_and_expired_cleanup", func(t *testing.T) {
		loaded, err = repo.SAMLLoginProvider(ctx, p.Slug)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM saml_flows WHERE tenant_id=$1`, tenant).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.ExecContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS now) INSERT INTO saml_flows(tenant_id,provider_id,provider_revision,state_hash,browser_hash,protocol_state_enc,created_at,expires_at) SELECT $1,$2,$3,decode('ff'||lpad(to_hex(n),62,'0'),'hex'),decode(repeat('11',32),'hex'),decode('01','hex'),stamp.now,stamp.now+interval '5 minutes' FROM generate_series(1,$4::int)n CROSS JOIN stamp`, tenant, p.ID, loaded.Revision, 10000-count); err != nil {
			t.Fatal(err)
		}
		input := sso.SAMLFlowInput{Provider: loaded, State: opaque(), RequestID: "bounded-request", BrowserDigest: bytes.Repeat([]byte{1}, 32)}
		if _, err := repo.SaveSAMLFlow(ctx, input); !errors.Is(err, sso.ErrFlow) {
			t.Fatal("full SAML flow cache accepted a new request", err)
		}
		if _, err := owner.ExecContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS now) UPDATE saml_flows SET created_at=stamp.now-interval '10 minutes',expires_at=stamp.now-interval '5 minutes' FROM stamp WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SaveSAMLFlow(ctx, input); err != nil {
			t.Fatal("expired flow cleanup could not admit a new request", err)
		}
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM saml_flows WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
			t.Fatal("expired flow rows retained", count, err)
		}
	})
	t.Log("SAML browser SQL verified encrypted durable requests, browser/provider/tenant binding, eight-way consumption and invitation admission, protocol/email-purpose separation, stable identity and disabled-account refusal")
}
