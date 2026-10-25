package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func testInvitationAdmissionRaces(t *testing.T, ctx context.Context, owner *sql.DB, repo *ConsoleStore, admin, provider string, ip netip.Addr) {
	t.Helper()
	defer owner.ExecContext(ctx, `DROP TRIGGER IF EXISTS reject_invitation_admin_audit ON audit_log; DROP FUNCTION IF EXISTS reject_invitation_admin_audit()`)
	issue := func(email string) web.IssuedInvitation {
		t.Helper()
		grant, err := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: email, Role: "member"}, ip)
		if err != nil {
			t.Fatal(err)
		}
		return grant
	}
	// Fail each administration audit after its write, preserving the old rows.
	for _, action := range []string{"invite.created", "invite.withdrawn"} {
		var candidate web.IssuedInvitation
		if action == "invite.withdrawn" {
			candidate = issue("withdraw-audit@example.com")
		}
		var before, after int
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM invites WHERE tenant_id=$1`, repo.Tenant).Scan(&before); err != nil {
			t.Fatal(err)
		}
		_, err := owner.ExecContext(ctx, `CREATE FUNCTION reject_invitation_admin_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='`+action+`' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_invitation_admin_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_invitation_admin_audit()`)
		if err != nil {
			t.Fatal(err)
		}
		if action == "invite.created" {
			grant, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "create-audit@example.com", Role: "member"}, ip)
			if e == nil || grant.Token != "" {
				t.Fatal("failed create audit returned an invitation")
			}
		} else {
			if e := repo.WithdrawInvitation(ctx, admin, candidate.ID, ip); e == nil {
				t.Fatal("failed withdrawal audit returned success")
			}
			var pending bool
			if e := owner.QueryRowContext(ctx, `SELECT cancelled_at IS NULL FROM invites WHERE id=$1`, candidate.ID).Scan(&pending); e != nil || !pending {
				t.Fatal("failed withdrawal retained cancellation", e)
			}
		}
		if err = owner.QueryRowContext(ctx, `SELECT count(*) FROM invites WHERE tenant_id=$1`, repo.Tenant).Scan(&after); err != nil || after != before {
			t.Fatal("administration audit failure retained a row", err)
		}
		if _, err = owner.ExecContext(ctx, `DROP TRIGGER reject_invitation_admin_audit ON audit_log; DROP FUNCTION reject_invitation_admin_audit()`); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(blocker *sql.Tx, done <-chan error) error {
		t.Helper()
		var pid int
		if err := blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for {
			var waiting bool
			if err := owner.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("invitation admission did not reach its authority lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := blocker.Commit(); err != nil {
			t.Fatal(err)
		}
		return <-done
	}
	blocker, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `UPDATE users SET role='member' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "demoted-issuer@example.com", Role: "member"}, ip)
		done <- e
	}()
	if err = wait(blocker, done); !errors.Is(err, web.ErrForbidden) {
		t.Fatal("demoted administrator issued invitation after lock wait", err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE users SET role='admin' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	candidate := issue("disabled-withdraw@example.com")
	blocker, err = owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	done = make(chan error, 1)
	go func() { done <- repo.WithdrawInvitation(ctx, admin, candidate.ID, ip) }()
	if err = wait(blocker, done); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("disabled administrator withdrew invitation", err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	blocker, err = owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `UPDATE identity_providers SET enabled=false WHERE id=$1`, provider); err != nil {
		t.Fatal(err)
	}
	done = make(chan error, 1)
	go func() {
		_, e := repo.IssueInvitation(ctx, admin, web.InvitationInput{Email: "disabled-provider@example.com", Role: "member", ProviderID: &provider}, ip)
		done <- e
	}()
	if err = wait(blocker, done); !errors.Is(err, web.ErrInviteProviderUnavailable) {
		t.Fatal("provider disabled while waiting but invitation issued", err)
	}
	if _, err = owner.ExecContext(ctx, `UPDATE identity_providers SET enabled=true WHERE id=$1`, provider); err != nil {
		t.Fatal(err)
	}
	t.Log("Invitation administration verified create/withdraw audit rollback and observed demoted-actor, disabled-actor and disabled-provider lock waits")
}
