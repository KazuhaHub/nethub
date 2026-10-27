package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
)

var _ relaystate.TrafficRepository = (*ObservationStore)(nil)

func (s *ObservationStore) ObserveTraffic(ctx context.Context, at time.Time, samples []relaystate.TrafficSample) error {
	if s == nil || s.DB == nil || at.IsZero() || len(samples) > relaystate.MaxProxies {
		return relaystate.ErrStorage
	}
	seen := map[string]bool{}
	for _, sample := range samples {
		if !sample.Valid() || seen[sample.DeviceID] {
			return relaystate.ErrStorage
		}
		seen[sample.DeviceID] = true
	}
	if len(samples) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	data, err := json.Marshal(samples)
	if err != nil {
		return relaystate.ErrStorage
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return relaystate.ErrStorage
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1025`)
	if err != nil {
		return relaystate.ErrStorage
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err = rows.Scan(&tenant); err != nil {
			rows.Close()
			return relaystate.ErrStorage
		}
		tenants = append(tenants, tenant)
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil || len(tenants) == 0 || len(tenants) > 1024 {
		return relaystate.ErrStorage
	}
	for _, tenant := range tenants {
		if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			return relaystate.ErrStorage
		}
		if _, err = tx.ExecContext(ctx, `SELECT public.record_relay_traffic($1::jsonb,$2)`, string(data), at.UTC()); err != nil {
			return relaystate.ErrStorage
		}
	}
	if tx.Commit() != nil {
		return relaystate.ErrStorage
	}
	return nil
}
