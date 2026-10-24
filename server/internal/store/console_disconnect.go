package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func (s *ConsoleStore) RequestDisconnect(ctx context.Context, actor, device string, ip netip.Addr) (web.DeviceDisconnect, error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return web.DeviceDisconnect{}, errors.New("invalid disconnect source")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.DeviceDisconnect{}, err
	}
	defer tx.Rollback()
	var active string
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, actor).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return web.DeviceDisconnect{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return web.DeviceDisconnect{}, err
	}
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT d.revoked FROM devices d JOIN users u ON u.tenant_id=d.tenant_id
WHERE d.id=$1 AND u.id=$2 AND u.disabled_at IS NULL AND (u.role='admin' OR d.owner_user_id=u.id) FOR UPDATE OF d`, device, actor).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return web.DeviceDisconnect{}, web.ErrDeviceUnavailable
	}
	if err != nil {
		return web.DeviceDisconnect{}, err
	}
	if !revoked {
		return web.DeviceDisconnect{}, web.ErrDeviceNotRevoked
	}
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT request_device_disconnect($1,$2)`, actor, device).Scan(&id); err != nil {
		return web.DeviceDisconnect{}, err
	}
	var audited bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM audit_log WHERE target_device_id=$1 AND action='device.disconnect_requested' AND payload->>'request_id'=$2)`, device, id).Scan(&audited); err != nil {
		return web.DeviceDisconnect{}, err
	}
	if !audited {
		payload, _ := json.Marshal(map[string]string{"request_id": id, "source_ip": ip.Unmap().String()})
		if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'device.disconnect_requested',$2,$3::jsonb)`, actor, device, string(payload)); err != nil {
			return web.DeviceDisconnect{}, err
		}
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT console_disconnect_status($1,$2)`, actor, device).Scan(&raw); err != nil {
		return web.DeviceDisconnect{}, err
	}
	var result web.DeviceDisconnect
	if json.Unmarshal(raw, &result) != nil || result.RequestID != id {
		return web.DeviceDisconnect{}, errors.New("disconnect receipt unavailable")
	}
	return result, tx.Commit()
}
