package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// RelayTrustStore is not wired into a public route yet. Each operation holds
// head-before-device locks and rechecks the authenticated credential at commit.
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
	tx, err := s.lock(ctx, c, id)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	var accepted sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT record_relay_trust_application($1,$2,$3,$4)`, id, g.ID, g.Number, g.Bundle().Fingerprint()).Scan(&accepted); err != nil {
		return time.Time{}, device.ErrUnavailable
	}
	if !accepted.Valid {
		return time.Time{}, device.ErrDenied
	}
	if tx.Commit() != nil {
		return time.Time{}, device.ErrUnavailable
	}
	return accepted.Time, nil
}
