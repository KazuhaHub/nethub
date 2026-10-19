package guiacme_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/KazuhaHub/nethub/server/internal/http01"
)

type lostSQLReply struct {
	*guiissuer.SQLStore
	want, hit string
}

func (s *lostSQLReply) Save(ctx context.Context, w guiissuer.Snapshot, p guiissuer.Progress) (guiissuer.Snapshot, error) {
	next, err := s.SQLStore.Save(ctx, w, p)
	if err == nil && (s.want == "proof_live" && p.Phase == "proof_live" || s.want == "issued_order" && p.Phase == "finalizing" && p.Order.Status == "valid") {
		s.hit = s.want
		return guiissuer.Snapshot{}, guiissuer.ErrDatabase
	}
	return next, err
}

type fixtureSQLBuffer struct{ bytes.Buffer }

func (b *fixtureSQLBuffer) Write(p []byte) (int, error) {
	if len(p) > 131072-b.Len() {
		return 0, guiissuer.ErrDatabase
	}
	return b.Buffer.Write(p)
}

// Administrative writes are restricted to the explicitly labelled disposable
// fixture. They seed public CSR metadata and inject lease/retry clock faults;
// they never admit a production device or substitute for authenticated enrollment.
func fixtureSQL(t *testing.T, b guiissuer.DockerBinding, run guiissuer.SQLRunner, statement string) []byte {
	t.Helper()
	if !strings.HasPrefix(b.Project, "nethub-csr-db-") && !strings.HasPrefix(b.Project, "nethub-stack-test-") {
		t.Fatal("database is outside the test namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := run(ctx, []byte("SELECT 1;\n")); err != nil {
		t.Fatal("fixture database immutable binding changed")
	}
	command := func(args ...string) *exec.Cmd {
		c := exec.CommandContext(ctx, "/usr/bin/docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
		c.Stderr = io.Discard
		c.WaitDelay = 2 * time.Second
		return c
	}
	inspect := command("inspect", "--type", "container", "--format", `{{index .Config.Labels "org.nethub.gui-issuer-test"}}`, b.ContainerID)
	label, err := inspect.Output()
	if err != nil || string(bytes.TrimSpace(label)) != b.Project {
		t.Fatal("database has no matching explicit fixture ownership label")
	}
	c := command("exec", "--interactive", "--user", "postgres", b.ContainerID, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1")
	c.Stdin = strings.NewReader("SET log_statement=none;SET log_min_duration_statement=-1;SET log_min_error_statement=panic;SET statement_timeout='10s';\n" + statement + ";\n")
	var output fixtureSQLBuffer
	c.Stdout = &output
	if c.Run() != nil || ctx.Err() != nil {
		t.Fatal("private fixture administration failed; raw diagnostics suppressed")
	}
	return bytes.TrimSpace(output.Bytes())
}

func TestPebbleCoordinatorDatabaseRecovery(t *testing.T) {
	id := os.Getenv("NETHUB_TEST_GUI_SQL_CONTAINER")
	if id == "" {
		t.Skip("requires an explicitly owned disposable PostgreSQL fixture alongside the genuine CA")
	}
	binding := guiissuer.DockerBinding{ContainerID: id, ImageID: os.Getenv("NETHUB_TEST_GUI_SQL_IMAGE"), Project: os.Getenv("NETHUB_TEST_GUI_SQL_PROJECT")}
	run, err := guiissuer.NewDockerSQLRunner(binding)
	if err != nil {
		t.Fatal("fixture host SQL runner unavailable")
	}
	guiacme.RunPebbleIssuerFixture(t, func(account *guiacme.AccountStore, publisher *http01.Publisher, roots *x509.CertPool, csr []byte, public string, reopen func() *guiacme.AccountStore) guiacme.Order {
		request, err := guicert.ValidateBoundCSR(csr, "abcdefgh.devices.example.test", public)
		if err != nil {
			t.Fatal(err)
		}
		// Constant IDs are isolated by a fresh explicitly labelled fixture;
		// collisions fail rather than replacing any pre-existing row.
		const tenant = "a1111111-1111-1111-1111-111111111111"
		const user = "a2222222-2222-2222-2222-222222222222"
		const device = "a3333333-3333-3333-3333-333333333333"
		const requestID = "a4444444-4444-4444-4444-444444444444"
		seed := fmt.Sprintf(`BEGIN;
INSERT INTO public.tenants(id,name) VALUES('%s','Isolated GUI issuer fixture');
INSERT INTO public.users(id,tenant_id,email,role) VALUES('%s','%s','fixture@example.test','member');
INSERT INTO public.devices(id,tenant_id,owner_user_id,platform,device_secret_hash,subdomain,agent_protocol_version,gui_public_key)
VALUES('%s','%s','%s','opnsense','fixture-not-an-authenticated-credential','abcdefgh','1.2.0','%s');
INSERT INTO public.gui_certificate_requests(id,tenant_id,device_id,assigned_host,gui_public_key,csr_der)
VALUES('%s','%s','%s','abcdefgh.devices.example.test','%s',decode('%s','hex'));COMMIT`, tenant, user, tenant, device, tenant, user, public, requestID, tenant, device, public, hex.EncodeToString(request.DER))
		fixtureSQL(t, binding, run, seed)
		job, err := run(context.Background(), []byte("SET SESSION AUTHORIZATION nethub_issuer;SELECT public.enqueue_gui_certificate_request('"+requestID+"');\n"))
		if err != nil {
			t.Fatal("fixture initial queue admission failed")
		}
		jobID := string(bytes.TrimSpace(job))
		store := &guiissuer.SQLStore{Run: run, Domain: "devices.example.test", AllowsURL: account.AllowsURL}
		work, err := store.Claim(context.Background())
		if err != nil || work == nil || work.Lease.ID != jobID || work.Lease.RequestID != requestID {
			t.Fatal("initial claim did not select the seeded original request")
		}
		fault := &lostSQLReply{SQLStore: store, want: "proof_live"}
		coordinator := &guiissuer.Coordinator{Store: fault, Account: account, Publisher: publisher, Roots: roots}
		interruptions := 0
		var firstOrder string
		deadline := time.Now().Add(75 * time.Second)
		for time.Now().Before(deadline) {
			result, err := coordinator.Step(context.Background(), *work)
			if err != nil {
				if fault.hit == "" || interruptions >= 2 {
					t.Fatal("unexpected combined coordinator failure")
				}
				interruptions++
				if _, err := store.Renew(context.Background(), *work); err == nil {
					t.Fatal("stale pre-checkpoint worker regained its lease")
				}
				changed := fixtureSQL(t, binding, run, fmt.Sprintf(`WITH changed AS (UPDATE public.gui_certificate_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id='%s' AND state='leased' AND lease_token='%s' RETURNING 1) SELECT count(*) FROM changed`, work.Lease.ID, work.Lease.Token))
				if string(changed) != "1" {
					t.Fatal("owned lease expiry fault was not injected")
				}
				previous := *work
				account = reopen()
				store = &guiissuer.SQLStore{Run: run, Domain: "devices.example.test", AllowsURL: account.AllowsURL}
				work, err = store.Claim(context.Background())
				if err != nil || work == nil || work.Lease.ID != jobID || work.Lease.RequestID != requestID || work.Lease.Token == previous.Lease.Token || work.Lease.Recoveries != interruptions || work.CSRFingerprint != previous.CSRFingerprint {
					t.Fatal("restart replaced original work or retained stale lease")
				}
				progress, err := store.Read(context.Background(), *work)
				if err != nil || progress.Order == nil {
					t.Fatal("committed order checkpoint did not recover")
				}
				if firstOrder == "" {
					firstOrder = progress.Order.URI
				} else if firstOrder != progress.Order.URI {
					t.Fatal("restart created another order")
				}
				want := "issued_order"
				if interruptions == 2 {
					want = ""
				}
				fault = &lostSQLReply{SQLStore: store, want: want}
				coordinator = &guiissuer.Coordinator{Store: fault, Account: account, Publisher: publisher, Roots: roots}
				continue
			}
			work = &result.Work
			if result.State == "issued" {
				if interruptions != 2 {
					t.Fatal("combined recovery faults did not both execute")
				}
				encoded := fixtureSQL(t, binding, run, fmt.Sprintf(`SELECT encode(chain_pem,'hex') FROM public.gui_certificate_generations WHERE id='%s' AND job_id='%s' AND request_id='%s'`, result.Generation, jobID, requestID))
				chain, err := hex.DecodeString(string(encoded))
				if err != nil {
					t.Fatal("persisted public chain encoding invalid")
				}
				if _, err := guicert.ValidateChain(chain, csr, work.Host, roots, time.Now()); err != nil {
					t.Fatal("database chain failed original-key independent trust verification")
				}
				counts := fixtureSQL(t, binding, run, fmt.Sprintf(`SELECT (SELECT count(*) FROM public.gui_certificate_jobs WHERE request_id='%s')::text||'|'||(SELECT count(*) FROM public.gui_certificate_generations WHERE job_id='%s')::text||'|'||(SELECT count(*) FROM public.audit_log WHERE target_device_id='%s' AND action='device.certificate_issued')::text`, requestID, jobID, device))
				if string(counts) != "1|1|1" {
					t.Fatal("restart duplicated job, issued generation or audit")
				}
				// Issued state retires the lease. Recover the exact final checkpoint
				// from the fixture administrator only for the independent CA count.
				order := fixtureSQL(t, binding, run, fmt.Sprintf(`SELECT checkpoint#>>'{order,finalize_url}' FROM public.gui_certificate_progress WHERE job_id='%s'`, jobID))
				t.Log("Combined real PostgreSQL/host runner/CA recovery passed two committed-save lost replies, expired-lease reclaim, stale-worker refusal, same original CSR/order, independently trusted persisted chain and one job/generation/audit")
				return guiacme.Order{FinalizeURL: string(order)}
			}
			if result.State == "waiting" {
				// Explicit fixture clock fault, not a claim about production delay.
				fixtureSQL(t, binding, run, fmt.Sprintf(`UPDATE public.gui_certificate_jobs SET next_attempt_at=clock_timestamp() WHERE id='%s' AND state='retry_wait'`, jobID))
				work, err = store.Claim(context.Background())
				if err != nil || work == nil || work.Lease.ID != jobID {
					t.Fatal("pending observation did not reclaim original job")
				}
			} else if result.State != "progressed" {
				t.Fatal("unexpected terminal combined issuance")
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("combined database/CA recovery exceeded its bound")
		return guiacme.Order{}
	})
}
