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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

func testOIDCBrowserAdmission(t *testing.T, ctx context.Context, owner, db, authz, backup *sql.DB) {
	var tenant, foreign string
	for _, id := range []*string{&tenant, &foreign} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('OIDC admission fixture') RETURNING id`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	user := func(email string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,'admin','fixture-only-hash') RETURNING id`, tenant, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin := user("flow-admin@example.com")
	user("flow-backup@example.com")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := providersecret.New(key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: cipher, ValidateOIDC: func(context.Context, web.OIDCProviderInput) error { return nil }}
	other := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: foreign}, ProviderSecrets: cipher}
	ip := netip.MustParseAddr("::ffff:192.0.2.226")
	provider := func(slug, issuer string) web.OIDCProvider {
		t.Helper()
		p, e := repo.CreateOIDCProvider(ctx, admin, web.OIDCProviderInput{Slug: slug, DisplayName: slug, IssuerURL: issuer, ClientID: "console", ClientSecret: "isolated-flow-client", Enabled: true}, ip)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	first := provider("first", "https://first-idp.example")
	second := provider("second", "https://second-idp.example")
	alias := provider("first-alias", "https://first-idp.example")
	opaque := func() string {
		t.Helper()
		raw := make([]byte, 32)
		if _, e := rand.Read(raw); e != nil {
			t.Fatal(e)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	type flowFixture struct {
		ID, Browser string
		Input       sso.FlowInput
	}
	flow := func(p web.OIDCProvider, invitation []byte) flowFixture {
		t.Helper()
		loaded, e := repo.LoginProvider(ctx, p.Slug)
		if e != nil {
			t.Fatal(e)
		}
		browser := opaque()
		browserHash, _ := sso.Digest(browser)
		input := sso.FlowInput{Provider: loaded, State: authoidc.State{Value: opaque(), Nonce: opaque(), Verifier: opaque(), Configuration: opaque()}, BrowserDigest: browserHash, InvitationDigest: invitation}
		expires, e := repo.SaveOIDCFlow(ctx, input)
		if e != nil || !expires.After(time.Now()) {
			t.Fatal("flow save", e)
		}
		stateHash, _ := sso.Digest(input.State.Value)
		var id string
		if e = owner.QueryRowContext(ctx, `SELECT id FROM oidc_flows WHERE state_hash=$1`, stateHash).Scan(&id); e != nil {
			t.Fatal(e)
		}
		return flowFixture{ID: id, Browser: browser, Input: input}
	}
	consume := func(f flowFixture) sso.ConsumedFlow {
		t.Helper()
		v, e := repo.ConsumeOIDCFlow(ctx, f.Input.Provider.Slug, f.Input.State.Value, f.Input.BrowserDigest)
		if e != nil {
			t.Fatal("flow consumption", e)
		}
		return v
	}
	issue := func(email string, restriction *string) (web.IssuedInvitation, []byte) {
		t.Helper()
		v, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: email, Role: "member", ProviderID: restriction}, ip)
		if e != nil {
			t.Fatal(e)
		}
		digest, e := auth.InvitationDigest(v.Token)
		if e != nil {
			t.Fatal(e)
		}
		return v, digest
	}
	identity := func(f sso.ConsumedFlow, subject, email string, verified bool) auth.ExternalIdentity {
		return auth.ExternalIdentity{FlowID: f.ID, ProviderID: f.Provider.ID, ProviderRevision: f.Provider.Revision, Issuer: f.Provider.Config.IssuerURL, Subject: subject, Email: email, EmailVerified: verified}
	}
	var serial atomic.Uint64
	record := func() auth.SessionRecord {
		n := serial.Add(1)
		token := sha256.Sum256(fmt.Appendf(nil, "oidc-session-%d", n))
		csrf := sha256.Sum256(fmt.Appendf(nil, "oidc-csrf-%d", n))
		now := time.Now().UTC()
		return auth.SessionRecord{TokenHash: token[:], CSRFHash: csrf[:], CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: ip, UserAgent: "OIDC SQL fixture"}
	}
	assertPending := func(f flowFixture) {
		t.Helper()
		var pending bool
		if e := owner.QueryRowContext(ctx, `SELECT consumed_at IS NULL AND protocol_state_enc IS NOT NULL FROM oidc_flows WHERE id=$1`, f.ID).Scan(&pending); e != nil || !pending {
			t.Fatal("invalid callback consumed flow", e)
		}
	}
	choices, e := repo.LoginProviders(ctx)
	if e != nil || len(choices) != 3 {
		t.Fatal("enabled catalog", e)
	}
	if choices, e = other.LoginProviders(ctx); e != nil || len(choices) != 0 {
		t.Fatal("foreign catalog", e)
	}
	f := flow(first, nil)
	var encrypted, stateHash, browserHash []byte
	if e = owner.QueryRowContext(ctx, `SELECT protocol_state_enc,state_hash,browser_hash FROM oidc_flows WHERE id=$1`, f.ID).Scan(&encrypted, &stateHash, &browserHash); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{f.Input.State.Value, f.Input.State.Nonce, f.Input.State.Verifier, f.Browser} {
		if bytes.Contains(encrypted, []byte(value)) {
			t.Fatal("raw flow secret persisted")
		}
	}
	wantState, _ := sso.Digest(f.Input.State.Value)
	if !bytes.Equal(stateHash, wantState) || !bytes.Equal(browserHash, f.Input.BrowserDigest) {
		t.Fatal("state/browser digests differ")
	}
	if _, e = cipher.Open(providersecret.Binding{TenantID: tenant, ProviderID: first.ID, Purpose: providersecret.OIDCClientSecret}, encrypted); e == nil {
		t.Fatal("flow envelope accepted as provider credential")
	}
	wrong, _ := sso.Digest(opaque())
	for _, attempt := range []struct {
		repo    *ConsoleStore
		slug    string
		browser []byte
	}{{repo, first.Slug, wrong}, {repo, second.Slug, f.Input.BrowserDigest}, {other, first.Slug, f.Input.BrowserDigest}} {
		if _, e = attempt.repo.ConsumeOIDCFlow(ctx, attempt.slug, f.Input.State.Value, attempt.browser); !errors.Is(e, sso.ErrFlow) {
			t.Fatal("wrong binding accepted", e)
		}
		assertPending(f)
	}
	var winners atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := repo.ConsumeOIDCFlow(ctx, first.Slug, f.Input.State.Value, f.Input.BrowserDigest)
			if e == nil {
				if v.State != f.Input.State {
					t.Error("state restore mismatch")
				}
				winners.Add(1)
			} else if !errors.Is(e, sso.ErrFlow) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("concurrent callback consumption", winners.Load())
	}
	var cleared bool
	if e = owner.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL AND protocol_state_enc IS NULL FROM oidc_flows WHERE id=$1`, f.ID).Scan(&cleared); e != nil || !cleared {
		t.Fatal("consumed protocol state retained", e)
	}
	intact := flow(first, nil)
	substituted := flow(first, nil)
	var material []byte
	if e = owner.QueryRowContext(ctx, `SELECT protocol_state_enc FROM oidc_flows WHERE id=$1`, intact.ID).Scan(&material); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.ExecContext(ctx, `UPDATE oidc_flows SET protocol_state_enc=$2 WHERE id=$1`, substituted.ID, material); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ConsumeOIDCFlow(ctx, first.Slug, substituted.Input.State.Value, substituted.Input.BrowserDigest); !errors.Is(e, sso.ErrFlow) {
		t.Fatal("cross-flow ciphertext accepted", e)
	}
	assertPending(substituted)
	freshRepository := &ConsoleStore{AuthStore: repo.AuthStore, ProviderSecrets: cipher}
	if restored, e := freshRepository.ConsumeOIDCFlow(ctx, first.Slug, intact.Input.State.Value, intact.Input.BrowserDigest); e != nil || restored.State != intact.Input.State {
		t.Fatal("fresh repository could not restore durable flow", e)
	}
	if _, e = repo.CreateExternalSession(ctx, identity(sso.ConsumedFlow{ID: f.ID, Provider: f.Input.Provider}, "unbound", "flow-admin@example.com", true), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("email match without invitation admitted", e)
	}
	grant, digest := issue("flow-invite@example.com", &first.ID)
	if _, e = repo.SaveOIDCFlow(ctx, sso.FlowInput{Provider: func() sso.LoginProvider {
		p, e := repo.LoginProvider(ctx, second.Slug)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}(), State: f.Input.State, BrowserDigest: f.Input.BrowserDigest, InvitationDigest: digest}); !errors.Is(e, sso.ErrFlow) {
		t.Fatal("wrong restricted provider started", e)
	}
	claim := consume(flow(first, digest))
	claimIdentity := identity(claim, "new-subject", "FLOW-INVITE@EXAMPLE.COM", true)
	accepted, e := repo.CreateExternalSession(ctx, claimIdentity, record())
	if e != nil || accepted.Email != "flow-invite@example.com" || accepted.Role != "member" {
		t.Fatal("SSO invitation activation", e)
	}
	if _, e = repo.CreateExternalSession(ctx, claimIdentity, record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("same flow admitted twice", e)
	}
	var passwordless, used bool
	if e = owner.QueryRowContext(ctx, `SELECT password_hash IS NULL FROM users WHERE id=$1`, accepted.ID).Scan(&passwordless); e != nil || !passwordless {
		t.Fatal("SSO account gained password", e)
	}
	if e = owner.QueryRowContext(ctx, `SELECT used_at IS NOT NULL FROM invites WHERE id=$1`, grant.ID).Scan(&used); e != nil || !used {
		t.Fatal("grant not consumed", e)
	}
	for _, p := range []web.OIDCProvider{first, alias} {
		login := consume(flow(p, nil))
		value, e := repo.CreateExternalSession(ctx, identity(login, "new-subject", "different@example.com", false), record())
		if e != nil || value.ID != accepted.ID || value.Email != accepted.Email {
			t.Fatal("bound subject or same-issuer alias login failed", e)
		}
	}
	sessions, e := auth.NewService(&repo.AuthStore, auth.Config{})
	if e != nil {
		t.Fatal(e)
	}
	serviceFlow := consume(flow(first, nil))
	serviceLogin, e := sessions.LoginExternal(ctx, identity(serviceFlow, "new-subject", "", false), ip, "OIDC SQL session service")
	if e != nil {
		t.Fatal("external session service", e)
	}
	if session, e := sessions.AuthenticatePassive(ctx, serviceLogin.Token); e != nil || session.User.ID != accepted.ID || session.CSRFToken != serviceLogin.CSRFToken {
		t.Fatal("OIDC session did not retain real synchronizer binding", e)
	}
	for _, p := range []web.OIDCProvider{first, second} {
		login := consume(flow(p, nil))
		if _, e = repo.CreateExternalSession(ctx, identity(login, "other-subject", accepted.Email, true), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
			t.Fatal("email-only account attachment", e)
		}
	}
	// A false verified claim must leave both the invitation and mailbox unused.
	falseGrant, falseDigest := issue("unverified@example.com", nil)
	unverified := consume(flow(first, falseDigest))
	if _, e = repo.CreateExternalSession(ctx, identity(unverified, "unverified", "unverified@example.com", false), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("unverified invitation admitted", e)
	}
	if e = owner.QueryRowContext(ctx, `SELECT used_at IS NULL FROM invites WHERE id=$1`, falseGrant.ID).Scan(&used); e != nil || !used {
		t.Fatal("unverified claim consumed grant", e)
	}
	// Restriction and mailbox changes after flow creation are checked at admission.
	restricted, restrictedDigest := issue("restriction-race@example.com", nil)
	raced := consume(flow(first, restrictedDigest))
	if _, e = owner.ExecContext(ctx, `UPDATE invites SET provider_id=$2 WHERE id=$1`, restricted.ID, second.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.CreateExternalSession(ctx, identity(raced, "restricted-subject", "restriction-race@example.com", true), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("changed provider restriction bypassed", e)
	}
	_, mailDigest := issue("existing-after-start@example.com", nil)
	mail := consume(flow(first, mailDigest))
	if _, e = owner.ExecContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,'existing-after-start@example.com','member','fixture-only-hash')`, tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.CreateExternalSession(ctx, identity(mail, "mailbox-subject", "existing-after-start@example.com", true), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("existing mailbox attached", e)
	}
	if _, e = owner.ExecContext(ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, accepted.ID); e != nil {
		t.Fatal(e)
	}
	disabled := consume(flow(first, nil))
	if _, e = repo.CreateExternalSession(ctx, identity(disabled, "new-subject", accepted.Email, true), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("disabled bound account admitted", e)
	}
	if _, e = owner.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, accepted.ID); e != nil {
		t.Fatal(e)
	}
	// Provider revisions and disabled state fence flows created before a change.
	stale := flow(first, nil)
	name := "Renamed first"
	if _, e = repo.UpdateOIDCProvider(ctx, admin, first.ID, web.OIDCProviderPatch{DisplayName: &name}, ip); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ConsumeOIDCFlow(ctx, first.Slug, stale.Input.State.Value, stale.Input.BrowserDigest); !errors.Is(e, sso.ErrFlow) {
		t.Fatal("stale provider revision consumed", e)
	}
	changedAfterExchange := consume(flow(first, nil))
	if _, e = repo.UpdateOIDCProvider(ctx, admin, first.ID, web.OIDCProviderPatch{DisplayName: &name}, ip); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.CreateExternalSession(ctx, identity(changedAfterExchange, "new-subject", accepted.Email, false), record()); !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("provider change after consumption admitted stale assertion", e)
	}
	stopped := flow(first, nil)
	no := false
	yes := true
	if _, e = repo.UpdateOIDCProvider(ctx, admin, first.ID, web.OIDCProviderPatch{Enabled: &no}, ip); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ConsumeOIDCFlow(ctx, first.Slug, stopped.Input.State.Value, stopped.Input.BrowserDigest); !errors.Is(e, sso.ErrFlow) {
		t.Fatal("disabled provider consumed", e)
	}
	if _, e = repo.UpdateOIDCProvider(ctx, admin, first.ID, web.OIDCProviderPatch{Enabled: &yes}, ip); e != nil {
		t.Fatal(e)
	}
	// Two verified subjects race for one invitation; exactly one identity wins.
	_, oneDigest := issue("single-claim@example.com", nil)
	contenders := []sso.ConsumedFlow{consume(flow(first, oneDigest)), consume(flow(first, oneDigest))}
	winners.Store(0)
	for index, value := range contenders {
		wg.Add(1)
		go func(index int, value sso.ConsumedFlow) {
			defer wg.Done()
			_, e := repo.CreateExternalSession(ctx, identity(value, fmt.Sprintf("contender-%d", index), "single-claim@example.com", true), record())
			if e == nil {
				winners.Add(1)
			} else if !errors.Is(e, auth.ErrInvalidCredentials) {
				t.Error(e)
			}
		}(index, value)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("invitation admitted competing subjects", winners.Load())
	}
	// A failure after account/identity/flow writes rolls all admission work back.
	rollbackGrant, rollbackDigest := issue("sso-audit-rollback@example.com", nil)
	rollbackPending := flow(first, rollbackDigest)
	rollbackFlow := consume(rollbackPending)
	if _, e = owner.ExecContext(ctx, `CREATE FUNCTION reject_oidc_login_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='auth.login' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_oidc_login_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_oidc_login_audit()`); e != nil {
		t.Fatal(e)
	}
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_oidc_login_audit ON audit_log;DROP FUNCTION IF EXISTS reject_oidc_login_audit()`)
	if _, e = repo.CreateExternalSession(ctx, identity(rollbackFlow, "rollback-subject", "sso-audit-rollback@example.com", true), record()); e == nil {
		t.Fatal("audit failure ignored")
	}
	var clean bool
	if e = owner.QueryRowContext(ctx, `SELECT f.consumed_at IS NOT NULL AND f.admitted_at IS NULL AND i.used_at IS NULL AND NOT EXISTS(SELECT FROM users WHERE tenant_id=$3 AND email='sso-audit-rollback@example.com') FROM oidc_flows f,invites i WHERE f.id=$1 AND i.id=$2`, rollbackFlow.ID, rollbackGrant.ID, tenant).Scan(&clean); e != nil || !clean {
		t.Fatal("admission audit failure left partial state", e)
	}
	if _, e = repo.ConsumeOIDCFlow(ctx, first.Slug, rollbackPending.Input.State.Value, rollbackPending.Input.BrowserDigest); !errors.Is(e, sso.ErrFlow) {
		t.Fatal("failed admission replayed consumed flow", e)
	}
	if _, e = owner.ExecContext(ctx, `DROP TRIGGER reject_oidc_login_audit ON audit_log;DROP FUNCTION reject_oidc_login_audit()`); e != nil {
		t.Fatal(e)
	}
	// Runtime authorization never gains flow storage; the private backup can read it.
	for role, shouldRead := range map[*sql.DB]bool{authz: false, backup: true} {
		tx, e := role.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.ExecContext(ctx, `SELECT count(*) FROM oidc_flows`)
		tx.Rollback()
		if (e == nil) != shouldRead {
			t.Fatal("flow role grant mismatch", shouldRead, e)
		}
		if !shouldRead {
			var denied *pgconn.PgError
			if !errors.As(e, &denied) || denied.Code != "42501" {
				t.Fatal("flow refusal was not a privilege denial", e)
			}
		}
	}
	waitBlocked := func(blocker *sql.Tx) {
		t.Helper()
		var pid int
		if e := blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(time.Second)
		for {
			var waiting bool
			if e := owner.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); e != nil {
				t.Fatal(e)
			}
			if waiting {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("OIDC operation did not reach expected SQL lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Expiry is evaluated after either a provider-row or flow-row wait, not just
	// in the preliminary bearer lookup. Both trials observe an actual SQL wait.
	for _, providerLock := range []bool{true, false} {
		pending := flow(first, nil)
		if _, e = owner.ExecContext(ctx, `UPDATE oidc_flows SET expires_at=clock_timestamp()+interval '250 milliseconds' WHERE id=$1`, pending.ID); e != nil {
			t.Fatal(e)
		}
		blocker, e := owner.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback()
		if providerLock {
			_, e = blocker.ExecContext(ctx, `SELECT id FROM identity_providers WHERE id=$1 FOR UPDATE`, first.ID)
		} else {
			_, e = blocker.ExecContext(ctx, `SELECT id FROM oidc_flows WHERE id=$1 FOR UPDATE`, pending.ID)
		}
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			_, e := repo.ConsumeOIDCFlow(ctx, first.Slug, pending.Input.State.Value, pending.Input.BrowserDigest)
			done <- e
		}()
		waitBlocked(blocker)
		for {
			var expired bool
			if e = owner.QueryRowContext(ctx, `SELECT expires_at<=clock_timestamp() FROM oidc_flows WHERE id=$1`, pending.ID).Scan(&expired); e != nil {
				t.Fatal(e)
			}
			if expired {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if e = blocker.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = <-done; !errors.Is(e, sso.ErrFlow) {
			t.Fatal("flow expired during lock wait but consumed", providerLock, e)
		}
	}
	// Admission also checks expiry after waiting for the account. Its prior
	// consume remains committed, but it cannot create a late session.
	late := flow(first, nil)
	lateConsumed := consume(late)
	if _, e = owner.ExecContext(ctx, `UPDATE oidc_flows SET expires_at=clock_timestamp()+interval '250 milliseconds' WHERE id=$1`, late.ID); e != nil {
		t.Fatal(e)
	}
	blocker, e := owner.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Rollback()
	if _, e = blocker.ExecContext(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, accepted.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := repo.CreateExternalSession(ctx, identity(lateConsumed, "new-subject", accepted.Email, false), record())
		done <- e
	}()
	waitBlocked(blocker)
	for {
		var expired bool
		if e = owner.QueryRowContext(ctx, `SELECT expires_at<=clock_timestamp() FROM oidc_flows WHERE id=$1`, late.ID).Scan(&expired); e != nil {
			t.Fatal(e)
		}
		if expired {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e = blocker.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, auth.ErrInvalidCredentials) {
		t.Fatal("flow expired during account wait but admitted", e)
	}
	for _, mailboxLock := range []bool{false, true} {
		email := fmt.Sprintf("sso-expiry-%t@example.com", mailboxLock)
		grant, digest := issue(email, nil)
		consumed := consume(flow(first, digest))
		if _, e = owner.ExecContext(ctx, `UPDATE invites SET expires_at=clock_timestamp()+interval '250 milliseconds' WHERE id=$1`, grant.ID); e != nil {
			t.Fatal(e)
		}
		blocker, e := owner.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback()
		if mailboxLock {
			e = lockInvitationEmail(ctx, blocker, tenant, email)
		} else {
			_, e = blocker.ExecContext(ctx, `SELECT id FROM invites WHERE id=$1 FOR UPDATE`, grant.ID)
		}
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			_, e := repo.CreateExternalSession(ctx, identity(consumed, email, email, true), record())
			done <- e
		}()
		waitBlocked(blocker)
		for {
			var expired bool
			if e = owner.QueryRowContext(ctx, `SELECT expires_at<=clock_timestamp() FROM invites WHERE id=$1`, grant.ID).Scan(&expired); e != nil {
				t.Fatal(e)
			}
			if expired {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if e = blocker.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = <-done; !errors.Is(e, auth.ErrInvalidCredentials) {
			t.Fatal("expired invitation admitted after SQL wait", mailboxLock, e)
		}
		var unused bool
		if e = owner.QueryRowContext(ctx, `SELECT used_at IS NULL FROM invites WHERE id=$1`, grant.ID).Scan(&unused); e != nil || !unused {
			t.Fatal("expired invitation consumed", e)
		}
	}
	t.Run("capacity_and_expired_cleanup", func(t *testing.T) { testOIDCFlowCapacity(t, ctx, owner, db, cipher) })
	if e = repo.SSOFailed(ctx, ip, "callback"); e != nil {
		t.Fatal(e)
	}
	if e = repo.SSOFailed(ctx, ip, f.Input.State.Value); e == nil {
		t.Fatal("arbitrary upstream detail accepted as audit phase")
	}
	var audit string
	if e = owner.QueryRowContext(ctx, `SELECT jsonb_agg(payload)::text FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{f.Input.State.Value, f.Input.State.Nonce, f.Input.State.Verifier, f.Browser, grant.Token, serviceLogin.Token, "isolated-flow-client"} {
		if strings.Contains(audit, secret) {
			t.Fatal("protocol or session credential reached audit")
		}
	}
	t.Log("OIDC SQL verified encrypted durable state, browser/slug/tenant binding, eight-way consumption, ciphertext clearing, revision/disable fences, issuer-subject login, invitation-only verified-email admission, alias identity matching, no email takeover, competing claims, disabled-account refusal and atomic admission/audit rollback; assertions are trusted fixtures, not IdP verification")
}
