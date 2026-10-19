package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
)

type ObservationStore struct{ DB *sql.DB }

var _ relaystate.Repository = (*ObservationStore)(nil)

func (s *ObservationStore) Observe(ctx context.Context, observations []relaystate.Observation) error {
	if s == nil || s.DB == nil || len(observations) > relaystate.MaxProxies {
		return relaystate.ErrStorage
	}
	seen := map[string]bool{}
	for _, observation := range observations {
		if !observation.Valid() || seen[observation.DeviceID] {
			return relaystate.ErrStorage
		}
		seen[observation.DeviceID] = true
	}
	if len(observations) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	data, err := json.Marshal(observations)
	if err != nil {
		return relaystate.ErrStorage
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return relaystate.ErrStorage
	}
	defer tx.Rollback()
	// Scope comes from database tenant rows, never from the relay response.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1025`)
	if err != nil {
		return relaystate.ErrStorage
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			return relaystate.ErrStorage
		}
		tenants = append(tenants, tenant)
	}
	readError := rows.Err()
	rows.Close()
	if readError != nil || len(tenants) == 0 || len(tenants) > 1024 {
		return relaystate.ErrStorage
	}
	for _, tenant := range tenants {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return relaystate.ErrStorage
		}
		// Skip busy devices so display-only observations do not delay authorization.
		if _, err := tx.ExecContext(ctx, `WITH active AS (
            SELECT d.id FROM devices d JOIN jsonb_to_recordset($1::jsonb) AS o(device_id uuid,subdomain text)
              ON d.id=o.device_id AND d.subdomain=o.subdomain
            WHERE d.tenant_id=$2 AND NOT d.revoked FOR UPDATE OF d SKIP LOCKED)
            UPDATE devices d SET last_seen_at=clock_timestamp() FROM active
            WHERE d.id=active.id AND d.tenant_id=$2 AND NOT d.revoked`, string(data), tenant); err != nil {
			return relaystate.ErrStorage
		}
	}
	if err := tx.Commit(); err != nil {
		return relaystate.ErrStorage
	}
	return nil
}
