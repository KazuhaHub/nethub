package store

import (
	"context"
	"encoding/json"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

var _ relayhook.DisconnectProcessor = (*RelayStore)(nil)

// ProcessDisconnects records only an already published memory denial. It never
// claims that an existing browser stream or control socket was observed closed.
func (s *RelayStore) ProcessDisconnects(ctx context.Context, ready func(relayhook.RevokedDevice) bool) error {
	if s == nil || s.DB == nil || ready == nil {
		return relayhook.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayhook.RevocationBudget)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return relayhook.ErrUnavailable
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1025`)
	if err != nil {
		return relayhook.ErrUnavailable
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err = rows.Scan(&tenant); err != nil {
			rows.Close()
			return relayhook.ErrUnavailable
		}
		tenants = append(tenants, tenant)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(tenants) > 1024 {
		return relayhook.ErrUnavailable
	}
	remaining := 128
	for _, tenant := range tenants {
		if remaining == 0 {
			break
		}
		if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return relayhook.ErrUnavailable
		}
		rows, err = tx.QueryContext(ctx, `SELECT r.id,r.device_id FROM device_disconnect_requests r JOIN devices d ON d.tenant_id=r.tenant_id AND d.id=r.device_id
WHERE r.tenant_id=$1 AND r.processed_at IS NULL AND d.revoked ORDER BY r.requested_at,r.id LIMIT $2
FOR UPDATE OF r SKIP LOCKED FOR SHARE OF d SKIP LOCKED`, tenant, remaining)
		if err != nil {
			return relayhook.ErrUnavailable
		}
		type pending struct{ id, device string }
		var requests []pending
		for rows.Next() {
			var request pending
			if err = rows.Scan(&request.id, &request.device); err != nil {
				rows.Close()
				return relayhook.ErrUnavailable
			}
			requests = append(requests, request)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return relayhook.ErrUnavailable
		}
		remaining -= len(requests)
		for _, request := range requests {
			if !ready(relayhook.RevokedDevice{TenantID: tenant, DeviceID: request.device}) {
				continue
			}
			if _, err = tx.ExecContext(ctx, `UPDATE device_disconnect_requests SET processed_at=clock_timestamp() WHERE id=$1 AND processed_at IS NULL`, request.id); err != nil {
				return relayhook.ErrUnavailable
			}
			payload, _ := json.Marshal(map[string]string{"request_id": request.id, "mechanism": "heartbeat_denial"})
			if _, err = tx.ExecContext(ctx, `SELECT append_audit('system',NULL,'device.disconnect_armed',$1,$2::jsonb)`, request.device, string(payload)); err != nil {
				return relayhook.ErrUnavailable
			}
		}
	}
	if tx.Commit() != nil {
		return relayhook.ErrUnavailable
	}
	return nil
}
