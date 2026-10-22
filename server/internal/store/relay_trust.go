package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// RelayTrustStore holds head-before-device locks and rechecks the authenticated
// credential through commit, independently of bearer verification in the API.
type RelayTrustStore struct {
	Enrollment *EnrollmentStore
	ServerName string
}

func (s *RelayTrustStore) lock(ctx context.Context, c device.Credential, id string) (*sql.Tx, error) {
	if s == nil || s.Enrollment == nil || s.Enrollment.DB == nil || c.TenantID == "" || c.Hash == "" {
		return nil, device.ErrUnavailable
	}
	tx, err := s.Enrollment.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, device.ErrUnavailable
	}
	var head bool
	if err := tx.QueryRowContext(ctx, `SELECT lock_relay_trust_head()`).Scan(&head); err != nil || !head {
		tx.Rollback()
		return nil, device.ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, c.TenantID); err != nil {
		tx.Rollback()
		return nil, device.ErrUnavailable
	}
	var hash string
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT device_secret_hash,revoked FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, c.TenantID).Scan(&hash, &revoked)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (hash != c.Hash || revoked) {
		tx.Rollback()
		return nil, device.ErrDenied
	}
	if err != nil {
		tx.Rollback()
		return nil, device.ErrUnavailable
	}
	return tx, nil
}

func (s *RelayTrustStore) Current(ctx context.Context, c device.Credential, id string) (*relaytrust.Generation, error) {
	tx, err := s.lock(ctx, c, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var data []byte
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(read_current_relay_trust($1),'null'::jsonb)`, s.ServerName).Scan(&data); err != nil {
		return nil, device.ErrUnavailable
	}
	var generation *relaytrust.Generation
	if string(data) != "null" {
		generation, err = relaytrust.DecodeGeneration(data, s.ServerName, time.Now())
		if err != nil {
			return nil, device.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return nil, device.ErrUnavailable
	}
	return generation, nil
}

func (s *RelayTrustStore) Acknowledge(ctx context.Context, c device.Credential, id string, g *relaytrust.Generation) (time.Time, error) {
	if s == nil || g == nil || g.Bundle() == nil || g.ServerName != s.ServerName {
		return time.Time{}, device.ErrDenied
	}
	return s.AcknowledgeReport(ctx, c, id, relaytrust.Report{GenerationID: g.ID, Number: g.Number, Fingerprint: g.Bundle().Fingerprint()})
}

func (s *RelayTrustStore) AcknowledgeReport(ctx context.Context, c device.Credential, id string, report relaytrust.Report) (time.Time, error) {
	if !report.Valid() {
		return time.Time{}, device.ErrDenied
	}
	tx, err := s.lock(ctx, c, id)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	var accepted sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT record_relay_trust_application($1,$2,$3,$4)`, id, report.GenerationID, report.Number, report.Fingerprint).Scan(&accepted); err != nil {
		return time.Time{}, device.ErrUnavailable
	}
	if !accepted.Valid {
		return time.Time{}, relaytrust.ErrChanged
	}
	if tx.Commit() != nil {
		return time.Time{}, device.ErrUnavailable
	}
	return accepted.Time, nil
}

func (s *RelayTrustStore) Health(ctx context.Context) error {
	_, err := s.currentPublic(ctx)
	return err
}

// currentPublic shares readiness and current-publication validation with
// bootstrap recovery. Neither path may bypass the public-history role fences.
func (s *RelayTrustStore) currentPublic(ctx context.Context) (*relaytrust.Generation, error) {
	if s == nil || s.Enrollment == nil || s.Enrollment.Health(ctx) != nil {
		return nil, device.ErrUnavailable
	}
	var ready bool
	err := s.Enrollment.DB.QueryRowContext(ctx, `SELECT
 public.lock_relay_trust_head() AND
 NOT EXISTS (SELECT FROM (VALUES('public.read_current_relay_trust(text)'),('public.lock_relay_trust_head()'),
 ('public.record_relay_trust_application(uuid,uuid,integer,text)')) f(signature)
 LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
 WHERE p.oid IS NULL OR NOT p.prosecdef OR p.proowner<>'nethub_owner'::regrole
 OR NOT has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS (SELECT FROM (VALUES('public.relay_trust_generations'),('public.relay_trust_head'),('public.relay_trust_applications')) f(name)
 JOIN pg_class c ON c.oid=to_regclass(f.name)
 WHERE NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
 AND (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled IN ('O','A')
 AND tgfoid='public.retain_relay_trust_history()'::regprocedure
 AND ((tgrelid='public.relay_trust_generations'::regclass AND tgname='relay_trust_generation_immutable')
 OR (tgrelid='public.relay_trust_applications'::regclass AND tgname='relay_trust_application_immutable')))=2`).Scan(&ready)
	if err != nil || !ready {
		return nil, device.ErrUnavailable
	}
	var data []byte
	if err := s.Enrollment.DB.QueryRowContext(ctx, `SELECT coalesce(read_current_relay_trust($1),'null'::jsonb)`, s.ServerName).Scan(&data); err != nil {
		return nil, device.ErrUnavailable
	}
	if string(data) == "null" {
		return nil, nil
	}
	generation, err := relaytrust.DecodeGeneration(data, s.ServerName, time.Now())
	if err != nil {
		return nil, device.ErrUnavailable
	}
	return generation, nil
}
