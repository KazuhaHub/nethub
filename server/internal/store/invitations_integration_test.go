package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testConsoleInvitations(t *testing.T, ctx context.Context, owner, db *sql.DB) {
	t.Helper()
	var tenant, foreignTenant string
	for _, scope := range []*string{&tenant, &foreignTenant} {
		if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('invitation fixture') RETURNING id`).Scan(scope); err != nil {
			t.Fatal(err)
		}
	}
	password := "a local invitation fixture passphrase"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user := func(scope, email, role string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,$4) RETURNING id`, scope, email, role, hash).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin := user(tenant, "invite-admin@example.com", "admin")
	user(tenant, "invite-backup@example.com", "admin")
	member := user(tenant, "invite-member@example.com", "member")
	foreign := user(foreignTenant, "invite-foreign@example.com", "admin")
	repo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}}
	foreignRepo := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: foreignTenant}}
	ip := netip.MustParseAddr("::ffff:192.0.2.223")
	issue := func(email string) web.IssuedInvitation {
		t.Helper()
		grant, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: email, Role: "member"}, ip)
		if e != nil {
			t.Fatal(e)
		}
		return grant
	}
	digest := func(grant web.IssuedInvitation) []byte {
		t.Helper()
		value, e := auth.InvitationDigest(grant.Token)
		if e != nil {
			t.Fatal(e)
		}
		return value
	}
	var sequence atomic.Uint64
	record := func() auth.SessionRecord {
		value := sequence.Add(1)
		token := sha256.Sum256([]byte(fmt.Sprintf("invitation-session-%d", value)))
		csrf := sha256.Sum256([]byte(fmt.Sprintf("invitation-csrf-%d", value)))
		now := time.Now().UTC()
		return auth.SessionRecord{TokenHash: token[:], CSRFHash: csrf[:], CreatedAt: now, ExpiresAt: now.Add(time.Hour), IP: ip, UserAgent: "invitation SQL fixture"}
	}
	assertUnused := func(grant web.IssuedInvitation, email string) {
		t.Helper()
		var unused bool
		var count int
		if e := owner.QueryRowContext(ctx, `SELECT used_at IS NULL FROM invites WHERE id=$1`, grant.ID).Scan(&unused); e != nil || !unused {
			t.Fatal("failed activation consumed invitation", e)
		}
		if e := owner.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND lower(email)=$2`, tenant, email).Scan(&count); e != nil || count != 0 {
			t.Fatal("failed activation retained account", e)
		}
	}
	for _, actor := range []string{member, foreign} {
		if _, e := repo.IssueInvitation(ctx, actor, web.InvitationInput{Email: "denied@example.com", Role: "member"}, ip); e == nil {
			t.Fatal("unprivileged invitation issuance")
		}
		if _, e := repo.Invitations(ctx, actor, web.UserQuery{Limit: 5}); e == nil {
			t.Fatal("unprivileged invitation listing")
		}
	}
	if _, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "INVITE-MEMBER@example.com", Role: "member"}, ip); !errors.Is(e, web.ErrUserExists) {
		t.Fatal("existing-account invitation accepted", e)
	}
	grant := issue(" New-Invite@Example.com ")
	var stored []byte
	var lifetime float64
	if e := owner.QueryRowContext(ctx, `SELECT token_hash,extract(epoch FROM expires_at-created_at) FROM invites WHERE id=$1`, grant.ID).Scan(&stored, &lifetime); e != nil || !bytes.Equal(stored, digest(grant)) || lifetime != 72*3600 {
		t.Fatal("invitation digest or lifetime mismatch", e)
	}
	info, e := repo.InspectInvitation(ctx, digest(grant))
	if e != nil || info.Email != "new-invite@example.com" || !info.PasswordAllowed || info.Providers == nil {
		t.Fatal("invitation inspection", e)
	}
	if _, e = foreignRepo.InspectInvitation(ctx, digest(grant)); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("foreign invitation inspected", e)
	}
	if _, e = foreignRepo.AcceptInvitation(ctx, digest(grant), hash, record()); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("foreign invitation activated", e)
	}
	page, e := repo.Invitations(ctx, admin, web.UserQuery{Limit: 1})
	if e != nil || len(page.Items) != 1 || page.Items[0].CreatedBy.ID != admin {
		t.Fatal("pending invitation scope", e)
	}
	encoded, _ := json.Marshal(page)
	if bytes.Contains(encoded, []byte(grant.Token)) || bytes.Contains(encoded, []byte(hex.EncodeToString(stored))) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(stored))) {
		t.Fatal("pending projection exposed bearer/digest")
	}
	var wg sync.WaitGroup
	success := make(chan auth.SessionRecord, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			value, e := repo.AcceptInvitation(ctx, digest(grant), hash, record())
			if e == nil {
				success <- value
			} else {
				failures <- e
			}
		})
	}
	wg.Wait()
	close(success)
	close(failures)
	if len(success) != 1 || len(failures) != 7 {
		t.Fatal("invitation consumption was not single-use", len(success), len(failures))
	}
	accepted := <-success
	for e := range failures {
		if !errors.Is(e, auth.ErrInviteInvalid) {
			t.Fatal("unexpected concurrent claim failure", e)
		}
	}
	var sessions, audits int
	var firstUse, again time.Time
	if e := owner.QueryRowContext(ctx, `SELECT used_at FROM invites WHERE id=$1`, grant.ID).Scan(&firstUse); e != nil {
		t.Fatal(e)
	}
	if e := owner.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, accepted.ID).Scan(&sessions); e != nil || sessions != 1 {
		t.Fatal("single-use claim produced extra sessions", e)
	}
	if e := owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='invite.accepted' AND payload->>'invitation_id'=$2`, tenant, grant.ID).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("claim audit missing or duplicated", e)
	}
	if _, e = repo.AcceptInvitation(ctx, digest(grant), hash, record()); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("used invitation replay", e)
	}
	if e = owner.QueryRowContext(ctx, `SELECT used_at FROM invites WHERE id=$1`, grant.ID).Scan(&again); e != nil || !again.Equal(firstUse) {
		t.Fatal("first-use timestamp changed", e)
	}
	cancelled := issue("withdrawn@example.com")
	if e = repo.WithdrawInvitation(ctx, member, cancelled.ID, ip); !errors.Is(e, web.ErrForbidden) {
		t.Fatal("member withdrew invite", e)
	}
	if e = repo.WithdrawInvitation(ctx, admin, cancelled.ID, ip); e != nil {
		t.Fatal(e)
	}
	if e = repo.WithdrawInvitation(ctx, admin, cancelled.ID, ip); e != nil {
		t.Fatal("withdrawal retry", e)
	}
	if _, e = repo.AcceptInvitation(ctx, digest(cancelled), hash, record()); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("withdrawn invitation activated", e)
	}
	if e = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='invite.withdrawn' AND payload->>'invitation_id'=$2`, tenant, cancelled.ID).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("withdrawal audit duplicated", e)
	}
	var provider, foreignProvider string
	for _, p := range []struct {
		scope string
		out   *string
	}{{tenant, &provider}, {foreignTenant, &foreignProvider}} {
		if e = owner.QueryRowContext(ctx, `INSERT INTO identity_providers(tenant_id,kind,slug,display_name,enabled) VALUES($1,'oidc','restricted','Restricted',true) RETURNING id`, p.scope).Scan(p.out); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "foreign-provider@example.com", Role: "member", ProviderID: &foreignProvider}, ip); !errors.Is(e, web.ErrInviteProviderUnavailable) {
		t.Fatal("foreign provider invitation", e)
	}
	bound, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "bound@example.com", Role: "member", ProviderID: &provider}, ip)
	if e != nil {
		t.Fatal(e)
	}
	info, e = repo.InspectInvitation(ctx, digest(bound))
	if e != nil || info.PasswordAllowed || len(info.Providers) != 1 || info.Providers[0].Slug != "restricted" {
		t.Fatal("restricted invitation metadata", e)
	}
	if _, e = repo.AcceptInvitation(ctx, digest(bound), hash, record()); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("local password bypassed provider restriction", e)
	}
	assertUnused(bound, "bound@example.com")
	// Existing accounts must never be attached or changed by an invitation.
	collision := issue("collision@example.com")
	existing := user(tenant, "collision@example.com", "member")
	if _, e = repo.AcceptInvitation(ctx, digest(collision), hash, record()); !errors.Is(e, auth.ErrInviteInvalid) {
		t.Fatal("existing account claimed by email", e)
	}
	var role string
	if e = owner.QueryRowContext(ctx, `SELECT role FROM users WHERE id=$1`, existing).Scan(&role); e != nil || role != "member" {
		t.Fatal("existing account mutated", e)
	}
	// Competing invitations for one mailbox share the same creation lease.
	one, two := issue("same-mailbox@example.com"), issue("same-mailbox@example.com")
	var admitted atomic.Int32
	result := make(chan error, 2)
	for _, candidate := range []web.IssuedInvitation{one, two} {
		wg.Go(func() {
			_, e := repo.AcceptInvitation(ctx, digest(candidate), hash, record())
			if e == nil {
				admitted.Add(1)
			}
			result <- e
		})
	}
	wg.Wait()
	close(result)
	if admitted.Load() != 1 {
		t.Fatal("competing invitation mailbox admitted twice")
	}
	for e := range result {
		if e != nil && !errors.Is(e, auth.ErrInviteInvalid) {
			t.Fatal(e)
		}
	}
	// Failure at either audit position must roll back consume, user and session.
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_invitation_audit ON audit_log; DROP FUNCTION IF EXISTS reject_invitation_audit()`)
	for index, action := range []string{"invite.accepted", "auth.login"} {
		email := fmt.Sprintf("audit-rollback-%d@example.com", index)
		candidate := issue(email)
		var before int
		if e = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&before); e != nil {
			t.Fatal(e)
		}
		if _, e = owner.ExecContext(ctx, `CREATE FUNCTION reject_invitation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='`+action+`' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_invitation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_invitation_audit()`); e != nil {
			t.Fatal(e)
		}
		if _, e = repo.AcceptInvitation(ctx, digest(candidate), hash, record()); e == nil {
			t.Fatal("audit fault activation succeeded")
		}
		assertUnused(candidate, email)
		var after int
		if e = owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&after); e != nil || after != before {
			t.Fatal("audit fault retained a partial event", e)
		}
		if _, e = owner.ExecContext(ctx, `DROP TRIGGER reject_invitation_audit ON audit_log; DROP FUNCTION reject_invitation_audit()`); e != nil {
			t.Fatal(e)
		}
	}
	sessionFault := issue("session-rollback@example.com")
	if _, e = owner.ExecContext(ctx, `CREATE FUNCTION reject_invitation_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture session failure'; END $$;CREATE TRIGGER reject_invitation_session BEFORE INSERT ON sessions FOR EACH ROW EXECUTE FUNCTION reject_invitation_session()`); e != nil {
		t.Fatal(e)
	}
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_invitation_session ON sessions; DROP FUNCTION IF EXISTS reject_invitation_session()`)
	if _, e = repo.AcceptInvitation(ctx, digest(sessionFault), hash, record()); e == nil {
		t.Fatal("session insertion fault accepted")
	}
	assertUnused(sessionFault, "session-rollback@example.com")
	if _, e = owner.ExecContext(ctx, `DROP TRIGGER reject_invitation_session ON sessions; DROP FUNCTION reject_invitation_session()`); e != nil {
		t.Fatal(e)
	}
	// Expiry is rechecked after both invitation-row and mailbox-lease waits.
	for _, lease := range []bool{false, true} {
		email := fmt.Sprintf("expiry-wait-%t@example.com", lease)
		candidate := issue(email)
		if _, e = owner.ExecContext(ctx, `UPDATE invites SET expires_at=clock_timestamp()+interval '200 milliseconds' WHERE id=$1`, candidate.ID); e != nil {
			t.Fatal(e)
		}
		blocker, e := owner.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback()
		var pid int
		if e = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
			t.Fatal(e)
		}
		if lease {
			e = lockInvitationEmail(ctx, blocker, tenant, email)
		} else {
			_, e = blocker.ExecContext(ctx, `SELECT id FROM invites WHERE id=$1 FOR UPDATE`, candidate.ID)
		}
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { _, e := repo.AcceptInvitation(ctx, digest(candidate), hash, record()); done <- e }()
		deadline := time.Now().Add(time.Second)
		for {
			var waiting bool
			if e = owner.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); e != nil {
				t.Fatal(e)
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("activation did not reach expected lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
		for {
			var expired bool
			if e = owner.QueryRowContext(ctx, `SELECT expires_at<=clock_timestamp() FROM invites WHERE id=$1`, candidate.ID).Scan(&expired); e != nil {
				t.Fatal(e)
			}
			if expired {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("invitation expiry not observed")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if e = blocker.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = <-done; !errors.Is(e, auth.ErrInviteInvalid) {
			t.Fatal("invitation expired while waiting but activated", lease, e)
		}
		assertUnused(candidate, email)
	}
	testInvitationAdmissionRaces(t, ctx, owner, repo, admin, provider, ip)
	testInvitationHTTP(t, ctx, repo, password, issue("http-invite@example.com"))
	if e = repo.InvitationFailed(ctx, ip); e != nil {
		t.Fatal(e)
	}
	var audit string
	if e = owner.QueryRowContext(ctx, `SELECT jsonb_agg(payload)::text FROM audit_log WHERE tenant_id=$1`, tenant).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{grant.Token, cancelled.Token, bound.Token, password, hash} {
		if strings.Contains(audit, secret) {
			t.Fatal("invitation credential reached audit")
		}
	}
	t.Log("Invitations verified hashed 72-hour grants, tenant/admin scope, eight-way single use, provider restrictions, no email takeover, competing mailbox claims, audit/session rollback, both expiry lock waits and real HTTPS session activation")
}

func testInvitationHTTP(t *testing.T, ctx context.Context, repo *ConsoleStore, password string, grant web.IssuedInvitation) {
	t.Helper()
	service, err := auth.NewService(&repo.AuthStore, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	logs := &bytes.Buffer{}
	handler, err := web.New(web.Config{Origin: origin, DeviceDomain: "router.example.com", Logger: slog.New(slog.NewJSONHandler(logs, nil))}, service, repo)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	request := func(path string, payload any, want int) ([]byte, *http.Response) {
		t.Helper()
		body, _ := json.Marshal(payload)
		r, e := http.NewRequestWithContext(ctx, "POST", origin+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(response.Body)
		if e != nil || response.StatusCode != want {
			t.Fatal("invitation HTTPS response", path, response.StatusCode, e)
		}
		return data, response
	}
	request("/api/v1/console/invites/inspect", map[string]string{"token": grant.Token}, 200)
	request("/api/v1/console/invites/accept", map[string]string{"token": grant.Token, "password": "short"}, 422)
	data, response := request("/api/v1/console/invites/accept", map[string]string{"token": grant.Token, "password": password}, 200)
	var session auth.Session
	if err = json.Unmarshal(data, &session); err != nil || session.User.Role != "member" || session.User.Email != "http-invite@example.com" {
		t.Fatal("HTTP invitation identity", err)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Name != "__Host-nethub_session" || bytes.Contains(data, []byte(cookies[0].Value)) {
		t.Fatal("HTTP invitation cookie boundary")
	}
	request("/api/v1/console/invites/accept", map[string]string{"token": grant.Token, "password": password}, 404)
	r, err := http.NewRequestWithContext(ctx, "GET", origin+"/api/v1/console/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Body.Close()
	active, err := io.ReadAll(current.Body)
	if err != nil || current.StatusCode != 200 || !bytes.Contains(active, []byte(session.CSRFToken)) {
		t.Fatal("HTTP invitation session not usable", err)
	}
	for _, secret := range []string{grant.Token, password, cookies[0].Value} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Fatal("invitation HTTPS credential logged")
		}
	}
}
