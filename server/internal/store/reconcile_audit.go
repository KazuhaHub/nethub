package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *EnrollmentStore) RecordReconcileEvents(ctx context.Context, credential device.Credential, request protocol.ReconcileAuditRequest) (bool, error) {
	if err := request.Validate(); err != nil {
		return false, err
	}
	tx, revoked, err := s.lockDevice(ctx, credential, request.DeviceID)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	for _, event := range request.Events {
		var inserted string
		err = tx.QueryRowContext(ctx, `INSERT INTO device_reconcile_events(tenant_id,device_id,event_id,kind,failure_count,first_at,last_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING event_id`, credential.TenantID, request.DeviceID, event.EventID, event.Kind, event.Count, event.FirstAt, event.LastAt).Scan(&inserted)
		if errors.Is(err, sql.ErrNoRows) {
			var kind string
			var count int64
			var first, last time.Time
			err = tx.QueryRowContext(ctx, `SELECT kind,failure_count,first_at,last_at FROM device_reconcile_events WHERE tenant_id=$1 AND device_id=$2 AND event_id=$3`, credential.TenantID, request.DeviceID, event.EventID).Scan(&kind, &count, &first, &last)
			if err == nil && (kind != event.Kind || count != event.Count || first.UTC().Format("2006-01-02T15:04:05.000000Z") != event.FirstAt || last.UTC().Format("2006-01-02T15:04:05.000000Z") != event.LastAt) {
				return false, device.ErrReconcileAuditConflict
			}
		}
		if err != nil {
			var failure *pgconn.PgError
			if errors.As(err, &failure) && failure.Code == "54000" {
				return false, device.ErrLimited
			}
			return false, device.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return false, device.ErrUnavailable
	}
	return revoked, nil
}
