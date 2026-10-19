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
	prefix := "SET log_statement=none; SET log_min_duration_statement=-1; SET log_min_duration_sample=-1; SET log_statement_sample_rate=0; SET log_min_error_statement=panic; SET standard_conforming_strings=on; SET SESSION AUTHORIZATION nethub_issuer;\n"
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
