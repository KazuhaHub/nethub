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
	"encoding/pem"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guiissuer"
	"github.com/jackc/pgx/v5/pgconn"
)

func issuerSQL(ctx context.Context, statement string) ([]byte, error) {
	command := exec.CommandContext(ctx, "psql", "-X", "-qAt", "--host", "/var/run/postgresql", "--username", "postgres", "--dbname", "nethub", "--set", "ON_ERROR_STOP=1", "--set", "VERBOSITY=sqlstate")
	command.Stdin = strings.NewReader("SET standard_conforming_strings=on; SET SESSION AUTHORIZATION nethub_issuer;\n" + statement + ";\n")
	return command.CombinedOutput()
}

func testGUIJobs(t *testing.T, f *enrollmentFixture, web *sql.DB, tenantA, tenantB string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	requests := &GUIRequestStore{Enrollment: f.repository, DeviceDomain: "devices.example.com"}
	queue := &GUIJobQueue{Requests: requests}
	if err := queue.Health(f.ctx); err != nil {
		t.Fatal("job admission not ready", err)
	}
	t.Run("readiness_requires_cancellation_guard", func(t *testing.T) {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices DISABLE TRIGGER devices_cancel_gui_jobs`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices ENABLE TRIGGER devices_cancel_gui_jobs`); err != nil {
				t.Fatal(err)
			}
		}()
		if queue.Health(f.ctx) == nil {
			t.Fatal("queue ready without revocation guard")
		}
	})
	newRequest := func(tenant string) (device.Assignment, device.Credential, GUIRequest) {
		t.Helper()
		r, _, _ := f.fresh(t, tenant)
		r.GUIPublicKey = base64.RawURLEncoding.EncodeToString(spki)
		a, err := f.repository.Register(f.ctx, r, f.issue)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{a.Subdomain + ".devices.example.com"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
		if err != nil {
			t.Fatal(err)
		}
		c := device.Credential{TenantID: tenant, Hash: r.SecretHash}
		request, err := requests.Admit(f.ctx, c, a.ID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		if err != nil {
			t.Fatal(err)
		}
		return a, c, request
	}
	query := func(statement string) []byte {
		t.Helper()
		body, err := issuerSQL(f.ctx, statement)
		if err != nil {
			t.Fatal("isolated issuer function failed")
		}
		return bytes.TrimSpace(body)
	}
	claim := func() *guiissuer.Snapshot {
		t.Helper()
		data := query(`SELECT coalesce(public.claim_gui_certificate_job(),'null'::jsonb)`)
		if string(data) == "null" {
			return nil
		}
		work, err := guiissuer.DecodeSnapshot(data, "devices.example.com", []string{"console.example.com"}, time.Now())
		if err != nil {
			t.Fatal("claimed job failed independent public request validation", err)
		}
		return &work
	}
	renew := func(work *guiissuer.Snapshot) *guiissuer.Snapshot {
		t.Helper()
		l := work.Lease
		data := query(fmt.Sprintf(`SELECT coalesce(public.renew_gui_certificate_lease('%s','%s',%d),'null'::jsonb)`, l.ID, l.Token, l.Version))
		if string(data) == "null" {
			return nil
		}
		next, err := guiissuer.DecodeSnapshot(data, "devices.example.com", nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return &next
	}
	release := func(work *guiissuer.Snapshot, reason string) bool {
		t.Helper()
		l := work.Lease
		return string(query(fmt.Sprintf(`SELECT public.release_gui_certificate_lease('%s','%s',%d,'%s')`, l.ID, l.Token, l.Version, reason))) == "t"
	}
	a, c, request := newRequest(tenantA)
	var group sync.WaitGroup
	ids := make(chan string, 8)
	failures := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			id, err := queue.Enqueue(f.ctx, c, a.ID)
			if err != nil {
				failures <- err
			} else {
				ids <- id
			}
		})
	}
	group.Wait()
	close(ids)
	close(failures)
	for err := range failures {
		t.Fatal("concurrent initial enqueue failed", err)
	}
	var id string
	for value := range ids {
		if id != "" && id != value {
			t.Fatal("duplicate initial certificate job")
		}
		id = value
	}
	if id == "" {
		t.Fatal("initial job missing")
	}
	var count int
	if err := f.owner.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE target_device_id=$1 AND action='device.certificate_queued'`, a.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("enqueue retry duplicated audit", err)
	}
	if _, err := queue.Enqueue(f.ctx, device.Credential{TenantID: tenantB, Hash: c.Hash}, a.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("cross-tenant queue admission succeeded", err)
	}
	for _, role := range []*sql.DB{web, f.repository.DB} {
		for _, statement := range []string{`SELECT id FROM public.gui_certificate_jobs`, `SELECT public.claim_gui_certificate_job()`} {
			tx, err := role.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.ExecContext(f.ctx, statement)
			tx.Rollback()
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatal("application can read/claim issuer work", err)
			}
		}
	}
	type claimed struct {
		data []byte
		err  error
	}
	claimedWork := make(chan claimed, 4)
	for range 4 {
		group.Go(func() {
			data, err := issuerSQL(f.ctx, `SELECT coalesce(public.claim_gui_certificate_job(),'null'::jsonb)`)
			claimedWork <- claimed{data, err}
		})
	}
	group.Wait()
	close(claimedWork)
	var work *guiissuer.Snapshot
	for result := range claimedWork {
		if result.err != nil {
			t.Fatal("concurrent isolated claim failed")
		}
		if string(bytes.TrimSpace(result.data)) == "null" {
			continue
		}
		if work != nil {
			t.Fatal("concurrent workers acquired the same live job")
		}
		value, err := guiissuer.DecodeSnapshot(bytes.TrimSpace(result.data), "devices.example.com", nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		work = &value
	}
	if work == nil || work.Lease.ID != id || work.Lease.RequestID != request.ID || work.Lease.DeviceID != a.ID || work.Lease.TenantID != tenantA {
		t.Fatal("claim lost original request identity")
	}
	if claim() != nil {
		t.Fatal("live lease was claimed twice")
	}
	work = testGUIProgress(t, f, work)
	advanced := renew(work)
	if advanced == nil || advanced.Lease.Version <= work.Lease.Version || advanced.Lease.Token != work.Lease.Token {
		t.Fatal("lease renewal failed")
	}
	if renew(work) != nil || release(work, "transient") {
		t.Fatal("stale lease version changed work")
	}
	if !release(advanced, "waiting") {
		t.Fatal("pending validation release failed")
	}
	if claim() != nil {
		t.Fatal("retry ignored its database schedule")
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	work = claim()
	if work == nil || work.Lease.Polls != 1 || work.Lease.Failures != 0 || work.Lease.Token == advanced.Lease.Token {
		t.Fatal("waiting consumed failure budget or reused lease")
	}
	if release(advanced, "policy") {
		t.Fatal("retired lease token changed new work")
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if renew(work) != nil {
		t.Fatal("expired lease renewed")
	}
	work = claim()
	if work == nil || work.Lease.Recoveries != 1 {
		t.Fatal("expired lease did not recover with a fenced identity")
	}
	blocker, err := f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	var blockerPID int
	if err := blocker.QueryRowContext(f.ctx, `SELECT pg_backend_pid() FROM devices WHERE id=$1 FOR UPDATE`, a.ID).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	l := work.Lease
	finished := make(chan claimed, 1)
	go func() {
		data, err := issuerSQL(f.ctx, fmt.Sprintf(`SELECT coalesce(public.renew_gui_certificate_lease('%s','%s',%d),'null'::jsonb)`, l.ID, l.Token, l.Version))
		finished <- claimed{data, err}
	}()
	for deadline := time.Now().Add(5 * time.Second); ; {
		var waiting bool
		if err := f.owner.QueryRowContext(f.ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease renewal did not wait for the assignment lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := blocker.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	result := <-finished
	if result.err != nil || string(bytes.TrimSpace(result.data)) != "null" {
		t.Fatal("renewal accepted a lease that expired while waiting for the device lock")
	}
	work = claim()
	if work == nil || work.Lease.Recoveries != 2 {
		t.Fatal("post-lock expired lease recovery failed")
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if renew(work) != nil || release(work, "transient") || claim() != nil {
		t.Fatal("revoked assignment retained issuer authority")
	}
	var state string
	if err := f.owner.QueryRowContext(f.ctx, `SELECT state FROM gui_certificate_jobs WHERE id=$1`, id).Scan(&state); err != nil || state != "cancelled" {
		t.Fatal("revocation did not cancel active job", err)
	}
	if _, err := queue.Enqueue(f.ctx, c, a.ID); !errors.Is(err, device.ErrDenied) {
		t.Fatal("revoked device queued work", err)
	}
	b, bc, _ := newRequest(tenantB)
	bid, err := queue.Enqueue(f.ctx, bc, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	work = claim()
	if work == nil || work.Lease.ID != bid || work.Lease.TenantID != tenantB {
		t.Fatal("global host claim crossed/misbound tenant")
	}
	if _, err := f.owner.ExecContext(f.ctx, `UPDATE gui_certificate_jobs SET failures=4 WHERE id=$1`, bid); err != nil {
		t.Fatal(err)
	}
	if !release(work, "transient") {
		t.Fatal("terminal transient release failed")
	}
	if err := f.owner.QueryRowContext(f.ctx, `SELECT state FROM gui_certificate_jobs WHERE id=$1`, bid).Scan(&state); err != nil || state != "failed" {
		t.Fatal("failure budget was not terminal", err)
	}
	if got, err := queue.Enqueue(f.ctx, bc, b.ID); err != nil || got != bid {
		t.Fatal("terminal initial job created a fresh issuance attempt", err)
	}
	if claim() != nil {
		t.Fatal("exhausted job was reclaimed")
	}
	// More blocked parents than the batch limit must not hide a later live job.
	var blocked []string
	for range 33 {
		a, c, _ := newRequest(tenantA)
		if _, err := queue.Enqueue(f.ctx, c, a.ID); err != nil {
			t.Fatal(err)
		}
		blocked = append(blocked, a.ID)
	}
	healthy, hc, _ := newRequest(tenantA)
	healthyID, err := queue.Enqueue(f.ctx, hc, healthy.ID)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err = f.owner.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	for _, id := range blocked {
		if _, err := blocker.ExecContext(f.ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, id); err != nil {
			t.Fatal(err)
		}
	}
	available := claim()
	if available == nil || available.Lease.ID != healthyID {
		t.Fatal("locked batch prefix starved unrelated ready work")
	}
	if !release(available, "policy") {
		t.Fatal("healthy fixture terminal release failed")
	}
	for _, id := range blocked {
		if _, err := blocker.ExecContext(f.ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Log("Durable initial queue/audit deduplication, no raw application access, bound private claim, lease token/version/expiry fencing, polling/backoff, bounded retry and revocation passed")
}
