package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/traffic"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func (s *ConsoleStore) Traffic(ctx context.Context, actor string, query web.TrafficQuery) (web.TrafficPage, error) {
	if !traffic.ValidMonth(query.Month) || query.Limit < 1 || query.Limit > 200 {
		return web.TrafficPage{}, web.ErrProviderInput
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// One coherent snapshot includes the administrator check, totals and page.
	// FOR SHARE rechecks live authority and requires a non-read-only transaction.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return web.TrafficPage{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, s.Tenant); err != nil {
		return web.TrafficPage{}, err
	}
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.TrafficPage{}, err
	}
	page := web.TrafficPage{Month: query.Month, Items: []web.TrafficDevice{}}
	var warning string
	err = tx.QueryRowContext(ctx, `SELECT warning_bytes::text,revision FROM tenant_traffic_settings WHERE tenant_id=$1`, s.Tenant).Scan(&warning, &page.WarningRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return web.TrafficPage{}, err
	}
	if err == nil && warning != "0" {
		page.WarningBytes = &warning
	}
	var first, last sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT coalesce(sum(in_bytes),0)::text,coalesce(sum(out_bytes),0)::text,
        coalesce(sum(in_bytes+out_bytes),0)::text,coalesce(sum(reset_events),0)::text,
        min(first_observed_at),max(last_observed_at)
        FROM relay_traffic_months WHERE tenant_id=$1 AND month_start=$2::date`, s.Tenant, query.Month+"-01").Scan(&page.InBytes, &page.OutBytes, &page.TotalBytes, &page.ResetEvents, &first, &last); err != nil {
		return web.TrafficPage{}, err
	}
	if first.Valid {
		value := first.Time.UTC()
		page.FirstObservedAt = &value
	}
	if last.Valid {
		value := last.Time.UTC()
		page.LastObservedAt = &value
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.device_id,coalesce(d.label,''),coalesce(d.hostname,''),d.id IS NULL,
        m.in_bytes::text,m.out_bytes::text,(m.in_bytes+m.out_bytes)::text,m.reset_events::text,
        m.first_observed_at,m.last_observed_at
        FROM relay_traffic_months m LEFT JOIN devices d ON d.tenant_id=m.tenant_id AND d.id=m.device_id
        WHERE m.tenant_id=$1 AND m.month_start=$2::date
          AND (nullif($3,'')::uuid IS NULL OR m.device_id>nullif($3,'')::uuid)
        ORDER BY m.device_id LIMIT $4`, s.Tenant, query.Month+"-01", query.AfterID, query.Limit+1)
	if err != nil {
		return web.TrafficPage{}, err
	}
	for rows.Next() {
		var item web.TrafficDevice
		if err = rows.Scan(&item.DeviceID, &item.Label, &item.Hostname, &item.Removed, &item.InBytes, &item.OutBytes, &item.TotalBytes, &item.ResetEvents, &item.FirstObservedAt, &item.LastObservedAt); err != nil {
			rows.Close()
			return web.TrafficPage{}, err
		}
		item.FirstObservedAt, item.LastObservedAt = item.FirstObservedAt.UTC(), item.LastObservedAt.UTC()
		page.Items = append(page.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.TrafficPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].DeviceID))
		page.NextCursor = &cursor
	}
	if err = tx.Commit(); err != nil {
		return web.TrafficPage{}, err
	}
	return page, nil
}

func (s *ConsoleStore) SetTrafficWarning(ctx context.Context, actor, value string, expected int64, ip netip.Addr) (web.TrafficWarning, error) {
	if value == "" || !traffic.ValidWarning(value) || expected < 0 || expected > 9007199254740991 || !ip.IsValid() || ip.Zone() != "" {
		return web.TrafficWarning{}, web.ErrProviderInput
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.TrafficWarning{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.TrafficWarning{}, err
	}
	before := "0"
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT warning_bytes::text,revision FROM tenant_traffic_settings WHERE tenant_id=$1 FOR UPDATE`, s.Tenant).Scan(&before, &revision)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return web.TrafficWarning{}, err
	}
	if revision != expected {
		return web.TrafficWarning{}, web.ErrTrafficChanged
	}
	result := web.TrafficWarning{Revision: revision}
	if value != "0" {
		result.WarningBytes = &value
	}
	if before == value {
		return result, tx.Commit()
	}
	if found {
		err = tx.QueryRowContext(ctx, `UPDATE tenant_traffic_settings SET warning_bytes=$2::numeric,revision=revision+1,modified_by_user_id=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND revision=$4 RETURNING revision`, s.Tenant, value, actor, expected).Scan(&result.Revision)
	} else {
		err = tx.QueryRowContext(ctx, `INSERT INTO tenant_traffic_settings(tenant_id,warning_bytes,revision,modified_by_user_id) VALUES($1,$2::numeric,1,$3) ON CONFLICT(tenant_id) DO NOTHING RETURNING revision`, s.Tenant, value, actor).Scan(&result.Revision)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return web.TrafficWarning{}, web.ErrTrafficChanged
	}
	if err != nil {
		return web.TrafficWarning{}, err
	}
	payload, _ := json.Marshal(map[string]any{"source_ip": ip.Unmap().String(), "previous_bytes": before, "warning_bytes": value, "previous_revision": revision, "revision": result.Revision})
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'traffic.warning_updated',NULL,$2::jsonb)`, actor, string(payload)); err != nil {
		return web.TrafficWarning{}, err
	}
	if err = tx.Commit(); err != nil {
		return web.TrafficWarning{}, err
	}
	return result, nil
}
