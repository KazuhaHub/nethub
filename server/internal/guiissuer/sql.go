package guiissuer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var ErrDatabase = errors.New("certificate issuer database operation unavailable")
var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// SQLRunner executes one bounded private psql process with input on stdin. It
// must use the trusted local PostgreSQL administrator socket, discard stderr
// and bound stdout to 128 KiB. It must not log input or put it in argv. The host
// administrator remains trusted; SET SESSION AUTHORIZATION is not a sandbox.
type SQLRunner func(context.Context, []byte) ([]byte, error)

type SQLStore struct {
	Run       SQLRunner
	Domain    string
	Excluded  []string
	AllowsURL func(string) bool
	Now       func() time.Time
}

// Ready checks the reserved identity and narrow executable schema before a host
// command contacts a CA or claims work. It never repairs role/schema drift.
func (s *SQLStore) Ready(ctx context.Context) error {
	statement := `SELECT current_user='nethub_issuer' AND session_user='nethub_issuer'
 AND EXISTS (SELECT FROM pg_roles r WHERE r.rolname=current_user AND NOT r.rolcanlogin
  AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreatedb AND NOT r.rolcreaterole
  AND NOT r.rolreplication AND NOT r.rolbypassrls
  AND NOT EXISTS (SELECT FROM pg_auth_members WHERE roleid=r.oid OR member=r.oid))
 AND has_schema_privilege(current_user,'public','USAGE')
 AND NOT has_schema_privilege(current_user,'public','CREATE')
 AND NOT has_function_privilege(current_user,'public.lookup_device_credential(uuid)','EXECUTE')
 AND NOT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE CASE WHEN n.nspname='public' AND c.relkind IN ('r','p','v','m','f') THEN
   has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
    OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
   WHEN n.nspname='public' AND c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE')
   ELSE false END)
 AND (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public' AND c.relname IN ('gui_certificate_requests','gui_certificate_jobs',
   'gui_certificate_progress','gui_certificate_generations') AND c.relrowsecurity AND c.relforcerowsecurity)=4
 AND NOT EXISTS (SELECT FROM (VALUES
  ('public.claim_gui_certificate_job()'),('public.renew_gui_certificate_lease(uuid,uuid,bigint)'),
  ('public.release_gui_certificate_lease(uuid,uuid,bigint,text)'),
  ('public.read_gui_certificate_progress(uuid,uuid,bigint)'),
  ('public.save_gui_certificate_progress(uuid,uuid,bigint,text,jsonb)'),
  ('public.finish_gui_certificate_job(uuid,uuid,bigint,bytea,text,timestamptz,timestamptz,timestamptz,timestamptz)')) f(signature)
  LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
  WHERE p.oid IS NULL OR NOT p.prosecdef OR p.proowner<>'nethub_owner'::regrole
   OR NOT has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND (SELECT count(*) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgenabled IN ('O','A') AND
  ((t.tgrelid='public.devices'::regclass AND t.tgname='devices_cancel_gui_jobs'
     AND t.tgfoid='public.cancel_changed_gui_certificate_jobs()'::regprocedure)
   OR (t.tgrelid='public.gui_certificate_jobs'::regclass AND t.tgname='gui_certificate_job_identity'
     AND t.tgfoid='public.guard_gui_certificate_job_identity()'::regprocedure)
   OR (t.tgrelid='public.gui_certificate_progress'::regclass AND t.tgname='gui_certificate_progress_identity'
     AND t.tgfoid='public.guard_gui_certificate_progress_identity()'::regprocedure)
   OR (t.tgrelid='public.gui_certificate_generations'::regclass AND t.tgname='gui_certificate_generation_immutable'
     AND t.tgfoid='public.retain_gui_certificate_generation()'::regprocedure)))=4`
	body, err := s.query(ctx, statement)
	if err != nil || !bytes.Equal(body, []byte("t")) {
		return ErrDatabase
	}
	return nil
}

func (s *SQLStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SQLStore) query(ctx context.Context, statement string) ([]byte, error) {
	if s.Run == nil || s.AllowsURL == nil || ctx.Err() != nil || len(statement) > 100000 || strings.ContainsRune(statement, 0) {
		return nil, ErrDatabase
	}
	// These settings precede private input and role reduction in every new
	// session. An external administrator's logging/proxy policy is still trusted.
	prefix := "SET log_statement=none; SET log_min_duration_statement=-1; SET log_min_duration_sample=-1; SET log_statement_sample_rate=0; SET log_min_error_statement=panic; SET statement_timeout='10s'; SET lock_timeout='5s'; SET idle_in_transaction_session_timeout='10s'; SET standard_conforming_strings=on; SET SESSION AUTHORIZATION nethub_issuer;\n"
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, err := s.Run(bounded, []byte(prefix+statement+";\n"))
	if err != nil || bounded.Err() != nil || len(body) > 131072 {
		return nil, ErrDatabase
	}
	return bytes.TrimSpace(body), nil
}

func leaseArgs(w Snapshot) (string, error) {
	l := w.Lease
	if !uuidPattern.MatchString(l.ID) || !uuidPattern.MatchString(l.Token) || l.Token == "00000000-0000-0000-0000-000000000000" || l.Version < 2 {
		return "", ErrSnapshot
	}
	return fmt.Sprintf("'%s','%s',%d", l.ID, l.Token, l.Version), nil
}

func sameWork(a, b Snapshot) bool {
	return a.Lease.ID == b.Lease.ID && a.Lease.TenantID == b.Lease.TenantID && a.Lease.DeviceID == b.Lease.DeviceID && a.Lease.RequestID == b.Lease.RequestID && a.Lease.Token == b.Lease.Token && a.Lease.Generation == b.Lease.Generation && a.Lease.Deadline.Equal(b.Lease.Deadline) && a.Host == b.Host && a.PublicKey == b.PublicKey && a.CSRFingerprint == b.CSRFingerprint && bytes.Equal(a.CSR, b.CSR)
}

func (s *SQLStore) next(body []byte, before *Snapshot) (Snapshot, error) {
	w, err := DecodeSnapshot(body, s.Domain, s.Excluded, s.now())
	if err != nil || before != nil && (!sameWork(*before, w) || w.Lease.Version != before.Lease.Version+1) {
		return Snapshot{}, ErrDatabase
	}
	return w, nil
}

// Claim returns nil only when no work is available. All malformed/fenced
// responses fail closed, without including raw database output in the error.
func (s *SQLStore) Claim(ctx context.Context) (*Snapshot, error) {
	body, err := s.query(ctx, "SELECT coalesce(public.claim_gui_certificate_job(),'null'::jsonb)")
	if err != nil {
		return nil, err
	}
	if bytes.Equal(body, []byte("null")) {
		return nil, nil
	}
	w, err := s.next(body, nil)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func (s *SQLStore) Renew(ctx context.Context, w Snapshot) (Snapshot, error) {
	args, err := leaseArgs(w)
	if err != nil {
		return Snapshot{}, err
	}
	body, err := s.query(ctx, "SELECT coalesce(public.renew_gui_certificate_lease("+args+"),'null'::jsonb)")
	if err != nil {
		return Snapshot{}, err
	}
	return s.next(body, &w)
}

func (s *SQLStore) Read(ctx context.Context, w Snapshot) (Progress, error) {
	args, err := leaseArgs(w)
	if err != nil {
		return Progress{}, err
	}
	body, err := s.query(ctx, "SELECT coalesce(public.read_gui_certificate_progress("+args+"),'null'::jsonb)")
	if err != nil {
		return Progress{}, err
	}
	p, err := DecodeProgress(body, w, s.AllowsURL)
	if err != nil {
		return Progress{}, ErrDatabase
	}
	return p, nil
}

func (s *SQLStore) Save(ctx context.Context, w Snapshot, p Progress) (Snapshot, error) {
	args, err := leaseArgs(w)
	if err != nil {
		return Snapshot{}, err
	}
	encoded, err := EncodeProgress(p, w, s.AllowsURL)
	if err != nil {
		return Snapshot{}, err
	}
	// Hex data and a codec-validated phase avoid embedding untrusted SQL text.
	statement := "SELECT coalesce(public.save_gui_certificate_progress(" + args + ",'" + p.Phase + "',convert_from(decode('" + hex.EncodeToString(encoded) + "','hex'),'UTF8')::jsonb),'null'::jsonb)"
	body, err := s.query(ctx, statement)
	if err != nil {
		return Snapshot{}, err
	}
	return s.next(body, &w)
}

func (s *SQLStore) Release(ctx context.Context, w Snapshot, reason string) error {
	args, err := leaseArgs(w)
	if err != nil {
		return err
	}
	switch reason {
	case "transient", "policy", "indeterminate_order", "waiting":
	default:
		return ErrDatabase
	}
	body, err := s.query(ctx, "SELECT public.release_gui_certificate_lease("+args+",'"+reason+"')")
	if err != nil || !bytes.Equal(body, []byte("t")) {
		return ErrDatabase
	}
	return nil
}

// Finish only persists material already validated by the coordinator against
// independent roots. Exact retries retain the same completion token/version.
func (s *SQLStore) Finish(ctx context.Context, w Snapshot, m Material) (string, error) {
	args, err := leaseArgs(w)
	if err != nil {
		return "", err
	}
	if len(m.PEM) == 0 || len(m.PEM) > 32768 || !fingerprintPattern.MatchString(m.Fingerprint) || m.NotBefore.IsZero() || !m.ValidUntil.After(m.NotBefore) || m.ValidUntil.After(m.NotAfter) || !m.RenewAfter.After(s.now()) || !m.RenewAfter.Before(m.ValidUntil) {
		return "", ErrMaterial
	}
	statement := fmt.Sprintf("SELECT coalesce(public.finish_gui_certificate_job(%s,decode('%s','hex'),'%s','%s','%s','%s','%s')::text,'null')", args, hex.EncodeToString(m.PEM), m.Fingerprint, m.NotBefore.UTC().Format(time.RFC3339Nano), m.NotAfter.UTC().Format(time.RFC3339Nano), m.ValidUntil.UTC().Format(time.RFC3339Nano), m.RenewAfter.UTC().Format(time.RFC3339Nano))
	body, err := s.query(ctx, statement)
	if err != nil || !uuidPattern.Match(body) {
		return "", ErrDatabase
	}
	return string(body), nil
}
