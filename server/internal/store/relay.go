package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

type RelayStore struct{ DB *sql.DB }

var _ relayhook.Repository = (*RelayStore)(nil)

// Authorize accepts only a payload already verified by the deployment keyring.
func (s *RelayStore) Authorize(ctx context.Context, identity protocol.ClaimPayload) error {
	if s == nil || s.DB == nil {
		return relayhook.ErrUnavailable
	}
	issued, err := time.Parse("2006-01-02T15:04:05.000000Z", identity.IssuedAt)
	if err != nil || issued.Format("2006-01-02T15:04:05.000000Z") != identity.IssuedAt {
		return relayhook.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, relayhook.Budget)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return relayhook.ErrUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, identity.TenantID); err != nil {
		return relayhook.ErrUnavailable
	}
	var matches bool
	err = tx.QueryRowContext(ctx, `SELECT true FROM devices WHERE id=$1 AND tenant_id=$2 AND subdomain=$3
        AND domain_claim_issued_at=$4 AND NOT revoked FOR SHARE`, identity.DeviceID, identity.TenantID, identity.Subdomain, issued).Scan(&matches)
	if errors.Is(err, sql.ErrNoRows) {
		return relayhook.ErrDenied
	}
	if err != nil || !matches || tx.Commit() != nil {
		return relayhook.ErrUnavailable
	}
	return nil
}
