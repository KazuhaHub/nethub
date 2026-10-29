package store

import (
	"context"
	"database/sql"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

var _ relayhook.ClaimRotationRepository = (*RelayStore)(nil)

// ClaimRotations exposes only the latest issuance floor for each rotated device.
// A bounded, repeatable-read scan never loads credential commitments or hashes.
func (s *RelayStore) ClaimRotations(ctx context.Context) ([]relayhook.RotatedClaim, error) {
	if s == nil || s.DB == nil {
		return nil, relayhook.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayhook.RevocationBudget)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, relayhook.ErrUnavailable
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1025`)
	if err != nil {
		return nil, relayhook.ErrUnavailable
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			return nil, relayhook.ErrUnavailable
		}
		tenants = append(tenants, tenant)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(tenants) > 1024 {
		return nil, relayhook.ErrUnavailable
	}
	rotated := []relayhook.RotatedClaim{}
	for _, tenant := range tenants {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return nil, relayhook.ErrUnavailable
		}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT ON (device_id) device_id,issued_at FROM device_rotations
 WHERE tenant_id=$1 ORDER BY device_id,issued_at DESC LIMIT $2`, tenant, relayhook.MaxRevocations-len(rotated)+1)
		if err != nil {
			return nil, relayhook.ErrUnavailable
		}
		for rows.Next() {
			value := relayhook.RotatedClaim{Device: relayhook.RevokedDevice{TenantID: tenant}}
			if err := rows.Scan(&value.Device.DeviceID, &value.IssuedAt); err != nil {
				rows.Close()
				return nil, relayhook.ErrUnavailable
			}
			rotated = append(rotated, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(rotated) > relayhook.MaxRevocations {
			return nil, relayhook.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return nil, relayhook.ErrUnavailable
	}
	return rotated, nil
}
