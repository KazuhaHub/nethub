package store

import (
	"context"
	"database/sql"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

var _ relayhook.RevocationRepository = (*RelayStore)(nil)

// Revocations reads a consistent tenant-scoped snapshot using existing authz grants.
func (s *RelayStore) Revocations(ctx context.Context) ([]relayhook.RevokedDevice, error) {
	if s == nil || s.DB == nil {
		return nil, relayhook.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayhook.RevocationBudget)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
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
		if err = rows.Scan(&tenant); err != nil {
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
	devices := []relayhook.RevokedDevice{}
	for _, tenant := range tenants {
		if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return nil, relayhook.ErrUnavailable
		}
		rows, err = tx.QueryContext(ctx, `SELECT id FROM devices WHERE tenant_id=$1 AND revoked ORDER BY id LIMIT $2`, tenant, relayhook.MaxRevocations-len(devices)+1)
		if err != nil {
			return nil, relayhook.ErrUnavailable
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return nil, relayhook.ErrUnavailable
			}
			devices = append(devices, relayhook.RevokedDevice{TenantID: tenant, DeviceID: id})
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(devices) > relayhook.MaxRevocations {
			return nil, relayhook.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return nil, relayhook.ErrUnavailable
	}
	return devices, nil
}
